package tun

import (
	"context"
	"crypto/md5"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// hiddenCmd runs a console program without flashing a window: these calls
// come from a GUI helper, and several of them run per access point.
func hiddenCmd(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(systemPath(name), args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

// systemPath resolves a bare command to its file under the Windows system
// directory, so a PATH without System32 cannot break routing setup.
func systemPath(name string) string {
	if strings.ContainsAny(name, `/\`) {
		return name
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	exe := name
	if !strings.HasSuffix(strings.ToLower(exe), ".exe") {
		exe += ".exe"
	}
	for _, dir := range []string{
		filepath.Join(root, "System32"),
		filepath.Join(root, "System32", "WindowsPowerShell", "v1.0"),
		filepath.Join(root, "Sysnative"),
	} {
		path := filepath.Join(dir, exe)
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			return path
		}
	}
	return name
}

const guid = "{4F5CDE94-D2A3-4AA5-A4A3-0FE6CB909E83}"
const interfaceName = "ZJU Connect"

// adapterFor picks the adapter name and GUID for this stack. A custom name
// (multi-point mode) gets its own GUID, derived from the name, so Windows
// creates a separate device per access point.
func adapterFor() (string, string) {
	if ifaceName == "" {
		return interfaceName, guid
	}
	sum := md5.Sum([]byte(ifaceName))
	derived := fmt.Sprintf("{%X-%X-%X-%X-%X}",
		sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
	return ifaceName, derived
}

type Endpoint struct {
	client client.Client

	dev       tun.Device
	readLock  sync.Mutex
	writeLock sync.Mutex
	ip        net.IP
}

func (ep *Endpoint) Write(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	ep.writeLock.Lock()
	defer ep.writeLock.Unlock()
	bufs := [][]byte{buf}

	_, err := ep.dev.Write(bufs, 0)
	if err != nil {
		return err
	}

	return nil
}

func (ep *Endpoint) Read(buf []byte) (int, error) {
	ep.readLock.Lock()
	defer ep.readLock.Unlock()
	bufs := [][]byte{buf}
	sizes := []int{1}

	_, err := ep.dev.Read(bufs, sizes, 0)
	if err != nil {
		return 0, err
	}

	return sizes[0], nil
}

func (s *Stack) AddRoute(target string) error {
	ipaddr, ipv4Net, err := net.ParseCIDR(target)
	if err != nil {
		return err
	}

	ip := ipaddr.To4()
	if ip == nil {
		return fmt.Errorf("not a valid IPv4 address")
	}

	// Drop a route an earlier helper left behind; otherwise the add fails.
	_ = hiddenCmd("route", "delete", ip.String()).Run()
	command := hiddenCmd("route", "add", ip.String(), "mask", net.IP(ipv4Net.Mask).String(), s.endpoint.ip.String(), "metric", "1")
	err = command.Run()
	if err != nil {
		return err
	}

	return nil
}

func NewStack(client client.Client, dnsHijack, fakeIP bool, ipResources []client.IPResource) (*Stack, error) {
	s := &Stack{}
	s.ipResources = ipResources
	s.fakeIP = fakeIP

	name, guidStr := adapterFor()
	adapterGUID, err := windows.GUIDFromString(guidStr)
	if err != nil {
		return nil, err
	}

	dev, err := tun.CreateTUNWithRequestedGUID(name, &adapterGUID, int(MTU))
	if err != nil {
		return nil, err
	}

	s.endpoint = &Endpoint{
		client: client,
	}

	s.endpoint.dev = dev

	nativeTunDevice := dev.(*tun.NativeTun)

	link := winipcfg.LUID(nativeTunDevice.LUID())

	s.endpoint.ip, err = client.IP()
	if err != nil {
		return nil, err
	}

	prefix, err := netip.ParsePrefix(s.endpoint.ip.String() + "/32")
	if err != nil {
		log.Printf("Parse prefix failed: %v", err) // Fail to set TUN IP is not a fatal problem, so we don't return an error
	}

	err = link.SetIPAddresses([]netip.Prefix{prefix})
	if err != nil {
		log.Printf("Set IP address failed: %v", err)
	}

	// Set MTU to 1400 otherwise error may occur when packets are large
	command := hiddenCmd("netsh", "interface", "ipv4", "set", "subinterface", name, fmt.Sprintf("mtu=%d", MTU), "store=persistent")
	err = command.Run()
	if err != nil {
		log.Printf("Run %s failed: %v", command.String(), err)
	}

	// The default route is only needed for full-tunnel use. In multi-point
	// mode each stack gets explicit routes instead, and a second default
	// route would fight the first.
	if ifaceName == "" {
		command = hiddenCmd("route", "add", "0.0.0.0", "mask", "0.0.0.0", s.endpoint.ip.String(), "metric", "9999")
		err = command.Run()
		if err != nil {
			log.Printf("Run %s failed: %v", command.String(), err)
		}
	}

	command = hiddenCmd("netsh", "interface", "ipv4", "delete", "dnsservers", name, "all")
	err = command.Run()
	if err != nil {
		log.Printf("Run %s failed: %v", command.String(), err)
	}
	if dnsHijack {
		dnsServerIP := s.endpoint.ip.String()
		if fakeIP {
			dnsServerIP = "198.18.0.1"
		}
		command = hiddenCmd("netsh", "interface", "ipv4", "add", "dnsservers", name, dnsServerIP)
		err = command.Run()
		if err != nil {
			log.Printf("Run %s failed: %v", command.String(), err)
		}
	}

	hook_func.RegisterTerminalFunc("Close Tun Device", func(ctx context.Context) error {
		dev.Close()
		closeCommand := hiddenCmd("netsh", "interface", "ipv4", "delete", "dnsservers", name, "all")
		return closeCommand.Run()
	})
	return s, nil
}
