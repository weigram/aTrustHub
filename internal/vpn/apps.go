package vpn

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	atrustclient "github.com/mythologyli/zju-connect/client/atrust"
)

// App is one application the aTrust server published to this user, as the
// official workbench lists it. It is not a proxy: the access point's
// tunnel already routes its addresses.
type App struct {
	ID            string
	Name          string
	Description   string
	AccessModel   string
	SubModel      string
	GroupName     string
	NodeGroupID   string
	NodeGroupName string
	IconPath      string
	AppAddress    string
	AccessAddress string
	AccessEntry   string
	Addresses     []AppAddress
}

// AppAddress is one backend address of a tunnel application.
type AppAddress struct {
	Protocol string
	Host     string
	Port     string
}

// TypeLabel is the application type as the UI shows it.
func (a App) TypeLabel() string {
	switch strings.ToUpper(a.AccessModel) {
	case "L3VPN":
		hasTCP, hasUDP := false, false
		for _, addr := range a.Addresses {
			switch strings.ToLower(addr.Protocol) {
			case "tcp":
				hasTCP = true
			case "udp":
				hasUDP = true
			case "all":
				hasTCP, hasUDP = true, true
			}
		}
		switch {
		case hasTCP && hasUDP:
			return "隧道模式（TCP/UDP协议）"
		case hasTCP:
			return "隧道模式（TCP）"
		case hasUDP:
			return "隧道模式（UDP）"
		default:
			return "隧道模式"
		}
	case "TUN2WEB":
		return "隧道转 Web"
	case "WEB":
		return "Web 模式"
	case "":
		return "应用"
	default:
		return a.AccessModel
	}
}

// AddressLines returns the backend addresses as "tcp host:port" lines.
func (a App) AddressLines() []string {
	lines := make([]string, 0, len(a.Addresses))
	for _, addr := range a.Addresses {
		host := addr.Host
		if addr.Port != "" {
			host = strings.TrimSuffix(host, ":") + ":" + addr.Port
		}
		line := strings.TrimSpace(addr.Protocol + " " + host)
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		switch {
		case a.AppAddress != "":
			lines = append(lines, a.AppAddress)
		case a.AccessAddress != "":
			lines = append(lines, a.AccessAddress)
		}
	}
	return lines
}

// AddressSummary is the first address and how many more there are.
func (a App) AddressSummary() string {
	lines := a.AddressLines()
	if len(lines) == 0 {
		return "—"
	}
	if len(lines) == 1 {
		return lines[0]
	}
	return fmt.Sprintf("%s 等 %d 条", lines[0], len(lines))
}

func appsFromZJU(in []atrustclient.App) []App {
	out := make([]App, 0, len(in))
	for _, app := range in {
		a := App{
			ID:            app.ID,
			Name:          app.Name,
			Description:   app.Description,
			AccessModel:   app.AccessModel,
			SubModel:      app.SubModel,
			GroupName:     app.GroupName,
			NodeGroupID:   app.NodeGroupID,
			NodeGroupName: app.NodeGroupName,
			IconPath:      app.IconPath,
			AppAddress:    app.AppAddress,
			AccessAddress: app.AccessAddress,
			AccessEntry:   app.AccessEntry,
		}
		for _, addr := range app.Addresses {
			a.Addresses = append(a.Addresses, AppAddress{
				Protocol: addr.Protocol,
				Host:     addr.Host,
				Port:     addr.Port,
			})
		}
		out = append(out, a)
	}
	return out
}

// Covers reports whether the app's addresses include host (an exact IP, a
// range A-B, or a CIDR). It is how the aggregate proxy knows which access
// point owns a target address.
func (a App) Covers(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	tip := net.ParseIP(host)
	for _, addr := range a.Addresses {
		h := strings.TrimSpace(addr.Host)
		if h == "" {
			continue
		}
		if h == host || strings.EqualFold(h, host) {
			return true
		}
		if tip == nil {
			continue
		}
		if strings.Contains(h, "/") {
			if _, ipnet, err := net.ParseCIDR(h); err == nil && ipnet.Contains(tip) {
				return true
			}
			continue
		}
		if i := strings.Index(h, "-"); i > 0 {
			lo := net.ParseIP(strings.TrimSpace(h[:i]))
			hi := net.ParseIP(strings.TrimSpace(h[i+1:]))
			if lo != nil && hi != nil && len(lo.To4()) == 4 && len(hi.To4()) == 4 {
				a4 := binary.BigEndian.Uint32(lo.To4())
				b4 := binary.BigEndian.Uint32(hi.To4())
				if a4 > b4 {
					a4, b4 = b4, a4
				}
				t4 := binary.BigEndian.Uint32(tip.To4())
				if t4 >= a4 && t4 <= b4 {
					return true
				}
			}
		}
	}
	return false
}

// Host returns the first backend host of a tunnel application.
func (a App) Host() string {
	if len(a.Addresses) > 0 {
		return a.Addresses[0].Host
	}
	return ""
}

// Hosts returns the unique backend hosts of a tunnel application, in order.
func (a App) Hosts() []string {
	seen := map[string]bool{}
	var out []string
	for _, addr := range a.Addresses {
		if addr.Host == "" || seen[addr.Host] {
			continue
		}
		seen[addr.Host] = true
		out = append(out, addr.Host)
	}
	return out
}

// PortsAt returns candidate TCP ports for the i-th address.
func (a App) PortsAt(i int) []int {
	if i < 0 || i >= len(a.Addresses) {
		return nil
	}
	return portsFor(a.Addresses[i].Port)
}

// TestPorts returns candidate TCP ports for the first address.
func (a App) TestPorts() []int {
	if len(a.Addresses) == 0 {
		return nil
	}
	return portsFor(a.Addresses[0].Port)
}

// portsFor narrows a port or port range to candidate service ports.
func portsFor(port string) []int {
	common := []int{443, 80, 8080, 8443, 22, 3389, 3306, 1521, 8000, 8888}
	if !strings.Contains(port, "-") {
		if n, err := strconv.Atoi(strings.TrimSpace(port)); err == nil && n > 0 && n <= 65535 {
			return []int{n}
		}
		return common
	}
	parts := strings.SplitN(port, "-", 2)
	lo, e1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	hi, e2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if e1 != nil || e2 != nil {
		return common
	}
	var out []int
	for _, port := range common {
		if port >= lo && port <= hi {
			out = append(out, port)
		}
	}
	if len(out) == 0 {
		out = []int{lo}
	}
	return out
}

// FirstDialAddr returns the first backend address as host:port for a
// connectivity test of a tunnel application.
func (a App) FirstDialAddr() (string, bool) {
	if len(a.Addresses) > 0 {
		addr := a.Addresses[0]
		if addr.Host == "" {
			return "", false
		}
		port := addr.Port
		if port == "" {
			port = "443"
		}
		return net.JoinHostPort(addr.Host, port), true
	}
	return "", false
}

// ProbeHosts expands every address host (including IP ranges like
// a-b and CIDRs) into individual IPs, de-duplicated and capped, for the
// connectivity check.
func (a App) ProbeHosts() []string {
	seen := map[string]bool{}
	var out []string
	for _, addr := range a.Addresses {
		for _, ip := range expandHostRange(addr.Host) {
			if ip == "" || seen[ip] {
				continue
			}
			seen[ip] = true
			out = append(out, ip)
			if len(out) >= 256 {
				return out
			}
		}
	}
	return out
}

// expandHostRange turns "10.0.0.1-10.0.0.5" or "10.0.0.0/30" into its IPs.
func expandHostRange(host string) []string {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil
	}
	if strings.Contains(host, "/") {
		ip, ipnet, err := net.ParseCIDR(host)
		if err != nil {
			return []string{host}
		}
		start := binary.BigEndian.Uint32(ip.Mask(ipnet.Mask).To4())
		end := binary.BigEndian.Uint32(ipnet.IP.To4())
		mask := binary.BigEndian.Uint32(ipnet.Mask)
		end |= ^mask
		var out []string
		for v := start; v >= start && v <= end; v++ {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], v)
			out = append(out, net.IP(b[:]).String())
			if len(out) >= 256 {
				break
			}
		}
		return out
	}
	if i := strings.Index(host, "-"); i > 0 {
		a := net.ParseIP(strings.TrimSpace(host[:i])).To4()
		b := net.ParseIP(strings.TrimSpace(host[i+1:])).To4()
		if a != nil && b != nil {
			start := binary.BigEndian.Uint32(a)
			end := binary.BigEndian.Uint32(b)
			if end < start {
				start, end = end, start
			}
			var out []string
			for v := start; v >= start && v <= end; v++ {
				var buf [4]byte
				binary.BigEndian.PutUint32(buf[:], v)
				out = append(out, net.IP(buf[:]).String())
				if len(out) >= 256 {
					break
				}
			}
			return out
		}
	}
	return []string{host}
}
