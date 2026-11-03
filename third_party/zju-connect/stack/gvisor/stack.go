package gvisor

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	clientpkg "github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/client/easyconnect"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/internal/ippool"
	"github.com/mythologyli/zju-connect/internal/zcdns"
	"github.com/mythologyli/zju-connect/log"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// ProcessExitOnShutdown lets a standalone helper end the process on a server
// SHUTDOWN; an embedder such as a GUI leaves it false and survives.
var ProcessExitOnShutdown = false

type Stack struct {
	gvisorStack *stack.Stack
	resolve     zcdns.LocalServer
	ipPool      *ippool.IPPool[[]clientpkg.DomainResource]

	endpoint *Endpoint
	ipMu     sync.Mutex
	ip       tcpip.Address
}

const NICID tcpip.NICID = 1
const MTU uint32 = 1400
const maxInboundPacketSize = 1500

type Endpoint struct {
	client clientpkg.Client

	l3Conn io.ReadWriteCloser

	dispatcher stack.NetworkDispatcher
}

func (ep *Endpoint) ParseHeader(*stack.PacketBuffer) bool {
	return true
}

func (ep *Endpoint) MTU() uint32 {
	return MTU
}

func (ep *Endpoint) SetMTU(mtu uint32) {
	log.Printf("don't support change MTU from %d to %d", MTU, mtu)
}

func (ep *Endpoint) MaxHeaderLength() uint16 {
	return 0
}

func (ep *Endpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (ep *Endpoint) SetLinkAddress(addr tcpip.LinkAddress) {}

func (ep *Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

func (ep *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	ep.dispatcher = dispatcher
}

func (ep *Endpoint) IsAttached() bool {
	return ep.dispatcher != nil
}

func (ep *Endpoint) Wait() {}

func (ep *Endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (ep *Endpoint) AddHeader(*stack.PacketBuffer) {}

func (ep *Endpoint) Close() {}

func (ep *Endpoint) SetOnCloseAction(func()) {}

// WritePackets is called when get packets from gVisor stack. Then it sends them to VPN server
func (ep *Endpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	for _, packetBuffer := range list.AsSlice() {
		buf := joinPacketSlices(packetBuffer.AsSlices())

		if ep.l3Conn != nil {
			n, err := ep.l3Conn.Write(buf)
			if err != nil {
				if errors.Is(err, clientpkg.ErrResourceNotFound) {
					log.Printf("%v", err)
					continue
				}

				// Server-initiated SHUTDOWN: known terminal state from
				// sangfor (cmd 0x08). No point retrying; run the registered
				// cleanup hooks (DNS revert, tun device close, etc.) and
				// exit so systemd / a wrapper can do a fresh login. This
				// is strictly better than panicking with a gvisor stack
				// trace, which obscures the actual cause.
				if errors.Is(err, easyconnect.ErrSangforShutdown) {
					log.Printf("WritePackets: 服务器 SHUTDOWN，运行清理钩子")
					if !hook_func.IsTerminal() {
						hook_func.ExecTerminalFunc(context.Background())
					}
					// The standalone helper exits so a wrapper can restart it
					// cleanly. Inside the GUI that would close the whole app,
					// so only the helper asks for an exit.
					if ProcessExitOnShutdown {
						os.Exit(2)
					}
					return list.Len(), nil
				}

				// A closed tunnel with gVisor still retransmitting is the
				// normal shape of 断开. Drop the packet: panicking here would
				// run on a gVisor timer goroutine, outside every recover, and
				// take the whole application down.
				if hook_func.IsTerminal() {
					return list.Len(), nil
				}
				logWriteDrop(err)
				continue
			}
			log.DebugPrintf("Send: wrote %d bytes", n)
			log.DebugDumpHex(buf[:n])
		}
	}

	return list.Len(), nil
}

var (
	dropMu     sync.Mutex
	dropCount  int
	dropLast   time.Time
	dropReason string
)

// logWriteDrop reports dropped outbound packets at most once every five
// seconds, together with how many were affected.
func logWriteDrop(err error) {
	dropMu.Lock()
	defer dropMu.Unlock()
	dropCount++
	message := err.Error()
	if message != dropReason {
		dropReason = message
		dropCount = 1
		dropLast = time.Now()
		log.Printf("WritePackets: 丢弃包（隧道不可写）：%v", err)
		return
	}
	if time.Since(dropLast) < 5*time.Second {
		return
	}
	log.Printf("WritePackets: 近 5 秒丢弃 %d 个包（隧道不可写）：%v", dropCount, err)
	dropCount = 0
	dropLast = time.Now()
}

func joinPacketSlices(slices [][]byte) []byte {
	total := 0
	for _, slice := range slices {
		total += len(slice)
	}
	buf := make([]byte, total)
	offset := 0
	for _, slice := range slices {
		offset += copy(buf[offset:], slice)
	}
	return buf
}

func NewStack(client clientpkg.Client) (*Stack, error) {
	s := &Stack{}

	s.gvisorStack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        true,
	})

	s.endpoint = &Endpoint{
		client: client,
	}

	tcpipErr := s.gvisorStack.CreateNIC(NICID, s.endpoint)
	if tcpipErr != nil {
		return nil, errors.New(tcpipErr.String())
	}

	ip, err := client.IP()
	if err != nil {
		return nil, err
	}

	addr := tcpip.AddrFromSlice(ip)
	s.ip = addr
	protoAddr := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: 32,
		},
		Protocol: ipv4.ProtocolNumber,
	}

	tcpipErr = s.gvisorStack.AddProtocolAddress(NICID, protoAddr, stack.AddressProperties{})
	if tcpipErr != nil {
		return nil, errors.New(tcpipErr.String())
	}
	clientpkg.RegisterIPUpdateHandler(client, s.updateIP)

	sOpt := tcpip.TCPSACKEnabled(true)
	s.gvisorStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)
	cOpt := tcpip.CongestionControlOption("cubic")
	s.gvisorStack.SetTransportProtocolOption(tcp.ProtocolNumber, &cOpt)
	s.gvisorStack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: NICID})

	return s, nil
}

func (s *Stack) updateIP(ip net.IP) error {
	ip = ip.To4()
	if ip == nil {
		return errors.New("virtual IP update is not IPv4")
	}
	newAddr := tcpip.AddrFromSlice(ip)
	s.ipMu.Lock()
	defer s.ipMu.Unlock()
	if newAddr == s.ip {
		return nil
	}
	protoAddr := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: newAddr, PrefixLen: 32},
		Protocol:          ipv4.ProtocolNumber,
	}
	if err := s.gvisorStack.AddProtocolAddress(NICID, protoAddr, stack.AddressProperties{}); err != nil {
		return errors.New(err.String())
	}
	if err := s.gvisorStack.RemoveAddress(NICID, s.ip); err != nil {
		_ = s.gvisorStack.RemoveAddress(NICID, newAddr)
		return errors.New(err.String())
	}
	s.ip = newAddr
	return nil
}

func (s *Stack) SetupResolve(r zcdns.LocalServer) {
	s.resolve = r
}

func (s *Stack) SetupIPPool(ipPool *ippool.IPPool[[]clientpkg.DomainResource]) {
	s.ipPool = ipPool
}

func (s *Stack) Run() {
	var connErr error
	s.endpoint.l3Conn, connErr = s.endpoint.client.NewL3Conn()
	if connErr != nil {
		panic(connErr)
	}
	// Read from VPN server and send to gVisor stack
	buf := make([]byte, maxInboundPacketSize)
	for {
		n, err := s.endpoint.l3Conn.Read(buf)
		if err != nil {
			if hook_func.IsTerminal() {
				return
			} else {
				panic(err)
			}
		}
		log.DebugPrintf("Recv: read %d bytes", n)
		log.DebugDumpHex(buf[:n])

		packetBuffer := makeInboundPacketBuffer(buf, n)
		s.endpoint.dispatcher.DeliverNetworkPacket(header.IPv4ProtocolNumber, packetBuffer)
		packetBuffer.DecRef()
	}
}

func makeInboundPacketBuffer(buf []byte, n int) *stack.PacketBuffer {
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(buf[:n]),
	})
}
