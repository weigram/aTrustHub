// Package model holds the configuration of the app: the aTrust access
// points it logs in to and the settings of the proxies it serves.
package model

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Routing is how the aggregate proxy picks the access point a new
// connection goes through.
type Routing string

const (
	// RoutingLatency sends a connection through the online access point
	// with the lowest recent dial latency.
	RoutingLatency Routing = "latency"
	// RoutingRoundRobin spreads connections over the online access points.
	RoutingRoundRobin Routing = "round_robin"
	// RoutingFailover uses the first online access point, in the order of
	// the list, and moves to the next one only when it fails.
	RoutingFailover Routing = "failover"
	// RoutingHash keeps one destination on one access point, by hashing
	// its host name.
	RoutingHash Routing = "hash"
)

// Routing values as the UI shows them.
var RoutingLabels = []struct {
	Value Routing
	Label string
}{
	{RoutingLatency, "延迟优先"},
	{RoutingRoundRobin, "轮询"},
	{RoutingFailover, "故障转移"},
	{RoutingHash, "按域名固定"},
}

// Label returns the Chinese name of the routing mode.
func (r Routing) Label() string {
	for _, entry := range RoutingLabels {
		if entry.Value == r {
			return entry.Label
		}
	}
	return string(r)
}

// Valid reports whether r is one of the modes.
func (r Routing) Valid() bool {
	for _, entry := range RoutingLabels {
		if entry.Value == r {
			return true
		}
	}
	return false
}

// AuthMode is how an access point authenticates.
type AuthMode string

const (
	// AuthModeAuto asks the server which methods it offers, then uses a
	// stored password if there is one and auth/psw is available; otherwise
	// it uses the first WeCom/enterprise external login.
	AuthModeAuto AuthMode = "auto"
	// AuthModePassword is aTrust's username and password login
	// (auth/psw), optionally with a TOTP secret.
	AuthModePassword AuthMode = "psw"
	// AuthModeWeCom is an external login, such as the WeCom QR code the
	// official client shows (auth/httpsOauth2 or auth/cas).
	AuthModeWeCom AuthMode = "wecom"
)

// AuthModeLabels are the modes as the UI shows them.
var AuthModeLabels = []struct {
	Value AuthMode
	Label string
}{
	{AuthModeAuto, "自动识别"},
	{AuthModePassword, "账号密码"},
	{AuthModeWeCom, "企业微信 / 单点登录"},
}

// Label returns the Chinese name of the mode.
func (m AuthMode) Label() string {
	for _, entry := range AuthModeLabels {
		if entry.Value == m {
			return entry.Label
		}
	}
	return string(m)
}

// Valid reports whether m is one of the modes.
func (m AuthMode) Valid() bool {
	return m == AuthModeAuto || m == AuthModePassword || m == AuthModeWeCom
}

// AccessPoint is one aTrust server the app logs in to. Its cred and
// TOTP secret live in the secret store, under the point's ID, not here.
type AccessPoint struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	// AuthMode is "psw" or "wecom"; empty means "psw".
	AuthMode    string `json:"authMode,omitempty"`
	LoginDomain string `json:"loginDomain,omitempty"`
	// SocksPort is the SOCKS5 port this access point serves on its own;
	// 0 disables it.
	SocksPort   int   `json:"socksPort"`
	InPool      bool  `json:"inPool"`
	AutoConnect bool  `json:"autoConnect"`
	CreatedAt   int64 `json:"createdAt,omitempty"`
	// Monitor asks the portal now and then whether this access point's login
	// is still the active one: another client signing in with the same account
	// takes the session over, and the tunnel can look fine while it is dead.
	// nil means the default, which is on.
	Monitor *bool `json:"monitor,omitempty"`
	// MonitorInterval is the check period in seconds; 0 means the default.
	MonitorInterval int `json:"monitorInterval,omitempty"`
	// DisabledApps holds application IDs the user took out of the tunnel,
	// because their addresses clash with the local network or with another
	// access point.
	DisabledApps []string `json:"disabledApps,omitempty"`
}

// defaultMonitorInterval is how often the session is probed when unset.
const defaultMonitorInterval = 300

// MonitorEnabled reports whether session validity monitoring is on. Existing
// configurations have no value stored, and those default to on.
func (p *AccessPoint) MonitorEnabled() bool {
	if p.Monitor == nil {
		return true
	}
	return *p.Monitor
}

// MonitorIntervalSeconds is the probe period, with the default applied and a
// floor so a typo cannot turn the app into a request flood.
func (p *AccessPoint) MonitorIntervalSeconds() int {
	if p.MonitorInterval <= 0 {
		return defaultMonitorInterval
	}
	if p.MonitorInterval < 30 {
		return 30
	}
	return p.MonitorInterval
}
func (p *AccessPoint) AppDisabled(id string) bool {
	for _, s := range p.DisabledApps {
		if s == id {
			return true
		}
	}
	return false
}

// SetAppDisabled records the choice and reports whether it changed anything.
func (p *AccessPoint) SetAppDisabled(id string, disabled bool) bool {
	if id == "" {
		return false
	}
	if p.AppDisabled(id) == disabled {
		return false
	}
	kept := make([]string, 0, len(p.DisabledApps)+1)
	for _, s := range p.DisabledApps {
		if s != id {
			kept = append(kept, s)
		}
	}
	if disabled {
		kept = append(kept, id)
	}
	p.DisabledApps = kept
	return true
}

// Settings are the app's own settings.
type Settings struct {
	// ListenHost is the address both the per-access-point and the
	// aggregate proxies bind to. Loopback by default.
	ListenHost       string  `json:"listenHost"`
	AggregatePort    int     `json:"aggregatePort"`
	AggregateEnabled bool    `json:"aggregateEnabled"`
	Routing          Routing `json:"routing"`
	// HealthIntervalSec is how often an online access point is probed
	// through its tunnel; 0 disables probing.
	HealthIntervalSec int  `json:"healthIntervalSec"`
	AutoReconnect     bool `json:"autoReconnect"`
	// SecretStore is where access point passwords are kept: "file" for the
	// local 0600 secrets.json, or "keychain" for the macOS Keychain. It is
	// read at startup, so a change takes effect after a restart.
	SecretStore string `json:"secretStore"`
	// TunEnabled remembers whether global TUN was on, and TunPointID which
	// access point it used, so the switch reflects the last state.
	TunEnabled bool   `json:"tunEnabled"`
	TunPointID string `json:"tunPointID"`
	// HideDock keeps the app out of the Dock (macOS), with a menu bar icon
	// instead, so closing the window leaves it running.
	HideDock bool `json:"hideDock"`
	// AutoLoginOptIn records that the user has been offered the auto-login
	// default. Access points do not log in at startup unless they ask for it.
	AutoLoginOptIn bool `json:"autoLoginOptIn"`
}

// Secret store choices.
const (
	SecretStoreFile     = "file"
	SecretStoreKeychain = "keychain"
)

// Config is the file the app keeps its configuration in.
type Config struct {
	Version  int           `json:"version"`
	Settings Settings      `json:"settings"`
	Points   []AccessPoint `json:"points"`
}

// CurrentVersion is the version of the configuration format.
const CurrentVersion = 1

// DefaultSettings returns the settings of a first run.
func DefaultSettings() Settings {
	return Settings{
		ListenHost:        "127.0.0.1",
		AggregatePort:     1080,
		AggregateEnabled:  true,
		Routing:           RoutingLatency,
		HealthIntervalSec: 60,
		AutoReconnect:     true,
		SecretStore:       SecretStoreFile,
	}
}

// NewID returns a random access point ID.
func NewID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail in practice; fall back to the clock
		// rather than taking the app down.
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

// Normalize fills defaults and cleans the user's input, so that the rest
// of the app can rely on the fields.
func (c *Config) Normalize() {
	if c.Version == 0 {
		c.Version = CurrentVersion
	}
	c.Settings.Normalize()
	seen := map[string]bool{}
	for i := range c.Points {
		p := &c.Points[i]
		p.Normalize()
		if p.ID == "" || seen[p.ID] {
			p.ID = NewID()
		}
		seen[p.ID] = true
	}
	c.EnsurePorts()
}

// Normalize fills the default settings.
func (s *Settings) Normalize() {
	if s.ListenHost == "" && s.AggregatePort == 0 && s.Routing == "" &&
		s.HealthIntervalSec == 0 && !s.AggregateEnabled && !s.AutoReconnect {
		*s = DefaultSettings()
		return
	}
	d := DefaultSettings()
	if strings.TrimSpace(s.ListenHost) == "" {
		s.ListenHost = d.ListenHost
	}
	if s.AggregatePort <= 0 || s.AggregatePort > 65535 {
		s.AggregatePort = d.AggregatePort
	}
	if !s.Routing.Valid() {
		s.Routing = d.Routing
	}
	if s.HealthIntervalSec < 0 {
		s.HealthIntervalSec = 0
	}
}

// Normalize cleans one access point.
func (p *AccessPoint) Normalize() {
	p.Server = CleanServer(p.Server)
	p.Username = strings.TrimSpace(p.Username)
	if p.AuthMode == "" || !AuthMode(p.AuthMode).Valid() {
		p.AuthMode = string(AuthModeAuto)
	}
	p.LoginDomain = strings.TrimSpace(p.LoginDomain)
	if p.LoginDomain == "" {
		// ZJU-Connect's aTrust default; servers list it as an auth
		// domain and the login fails without one.
		p.LoginDomain = "Radius"
	}
	if p.Port == 0 {
		p.Port = 443
	}
	if p.Name == "" {
		p.Name = p.Server
		if p.Name == "" {
			p.Name = "未命名接入点"
		}
	}
	if p.SocksPort < 0 || p.SocksPort > 65535 {
		p.SocksPort = 0
	}
	if p.CreatedAt == 0 {
		p.CreatedAt = time.Now().Unix()
	}
}

// ParseAccessAddress turns what the aTrust client calls an access address,
// such as https://vpn.example.com:443, into the server and port the
// client needs. A missing scheme means https, a missing port means 443, and
// a path or query is ignored.
func ParseAccessAddress(raw string) (string, int, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", 0, errors.New("接入地址不能为空")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", 0, fmt.Errorf("接入地址无效：%w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", 0, errors.New("接入地址必须是 http(s):// 开头")
	}
	if u.User != nil {
		return "", 0, errors.New("接入地址不能包含用户名")
	}
	host := u.Hostname()
	if host == "" {
		return "", 0, errors.New("接入地址缺少主机名")
	}
	port := 443
	if p := u.Port(); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, errors.New("接入地址的端口必须在 1–65535 之间")
		}
	}
	return host, port, nil
}

// FormatAccessAddress is the inverse of ParseAccessAddress, for the editor.
func FormatAccessAddress(server string, port int) string {
	if port == 0 || port == 443 {
		host := server
		if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
			host = "[" + host + "]"
		}
		return "https://" + host
	}
	return "https://" + net.JoinHostPort(server, strconv.Itoa(port))
}

// CleanServer turns what the user typed into a bare host name: it drops a
// scheme, a path and a port, which has a field of its own.
func CleanServer(server string) string {
	s := strings.TrimSpace(server)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.Trim(s, "[]")
	return strings.TrimSpace(s)
}

// Validate checks what the user entered, in the words the dialog shows.
func (c *Config) Validate() error {
	if err := c.Settings.Validate(); err != nil {
		return err
	}
	for i := range c.Points {
		if err := c.Points[i].Validate(); err != nil {
			return fmt.Errorf("%s：%w", c.Points[i].Name, err)
		}
	}
	return nil
}

// Validate checks the settings.
func (s *Settings) Validate() error {
	if s.SecretStore != SecretStoreKeychain {
		s.SecretStore = SecretStoreFile
	}
	if s.ListenHost == "" {
		return errors.New("监听地址不能为空")
	}
	if s.AggregatePort < 1 || s.AggregatePort > 65535 {
		return errors.New("统一入口端口必须在 1–65535 之间")
	}
	if !s.Routing.Valid() {
		return errors.New("分流模式无效")
	}
	if s.HealthIntervalSec < 0 {
		return errors.New("健康检查间隔不能为负")
	}
	return nil
}

// Validate checks one access point.
func (p *AccessPoint) Validate() error {
	if p.Server == "" {
		return errors.New("服务器地址不能为空")
	}
	if strings.ContainsAny(p.Server, " /?#") {
		return errors.New("服务器地址只能是主机名或 IP")
	}
	if p.Port < 1 || p.Port > 65535 {
		return errors.New("端口必须在 1–65535 之间")
	}
	switch AuthMode(p.AuthMode) {
	case AuthModeAuto:
		// The server decides; a stored password makes auth/psw the first
		// choice, otherwise an external login is used.
	case AuthModeWeCom:
		// The QR login has no username; the server tells us who it is.
	default:
		if p.Username == "" {
			return errors.New("用户名不能为空")
		}
	}
	if p.SocksPort < 0 || p.SocksPort > 65535 {
		return errors.New("SOCKS5 端口必须在 0–65535 之间")
	}
	if !p.InPool && p.SocksPort == 0 {
		return errors.New("至少勾选统一入口，或填一个独立 SOCKS5 端口")
	}
	return nil
}

// EnsurePorts gives every access point a SOCKS5 port of its own that does
// not collide with another one or with the aggregate proxy.
func (c *Config) EnsurePorts() {
	used := map[int]bool{c.Settings.AggregatePort: true}
	next := 1081
	for i := range c.Points {
		p := &c.Points[i]
		if p.SocksPort > 0 && !used[p.SocksPort] && p.SocksPort != c.Settings.AggregatePort {
			used[p.SocksPort] = true
			continue
		}
		if p.SocksPort == 0 {
			// 0 means no per-point proxy, which is a choice, not a gap.
			continue
		}
		for used[next] || next == c.Settings.AggregatePort {
			next++
		}
		p.SocksPort = next
		used[next] = true
		next++
	}
}

// NextSocksPort returns a free per-point SOCKS5 port.
func (c *Config) NextSocksPort() int {
	c.EnsurePorts()
	used := map[int]bool{c.Settings.AggregatePort: true}
	for _, p := range c.Points {
		if p.SocksPort > 0 {
			used[p.SocksPort] = true
		}
	}
	for port := 1081; port <= 65535; port++ {
		if !used[port] {
			return port
		}
	}
	return 1081
}

// Find returns the point with id, or nil.
func (c *Config) Find(id string) *AccessPoint {
	for i := range c.Points {
		if c.Points[i].ID == id {
			return &c.Points[i]
		}
	}
	return nil
}

// Index returns the position of the point with id, or -1.
func (c *Config) Index(id string) int {
	for i := range c.Points {
		if c.Points[i].ID == id {
			return i
		}
	}
	return -1
}

// Add appends a point, giving it an ID and a free SOCKS5 port when it has
// none.
func (c *Config) Add(p AccessPoint) *AccessPoint {
	p.Normalize()
	if p.ID == "" {
		p.ID = NewID()
	}
	if p.SocksPort == 0 {
		p.SocksPort = c.NextSocksPort()
	}
	c.Points = append(c.Points, p)
	c.EnsurePorts()
	return &c.Points[len(c.Points)-1]
}

// Update replaces the point with the same ID and returns it.
func (c *Config) Update(p AccessPoint) (*AccessPoint, error) {
	i := c.Index(p.ID)
	if i < 0 {
		return nil, errors.New("接入点不存在")
	}
	p.Normalize()
	c.Points[i] = p
	c.EnsurePorts()
	return &c.Points[i], nil
}

// Remove deletes the point with id.
func (c *Config) Remove(id string) bool {
	i := c.Index(id)
	if i < 0 {
		return false
	}
	c.Points = append(c.Points[:i], c.Points[i+1:]...)
	return true
}
