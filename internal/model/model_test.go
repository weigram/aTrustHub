package model

import (
	"strings"
	"testing"
)

func TestCleanServer(t *testing.T) {
	cases := map[string]string{
		"https://vpn.example.edu.cn/portal": "vpn.example.edu.cn",
		"vpn.example.edu.cn:8443":           "vpn.example.edu.cn",
		"  10.0.0.1  ":                      "10.0.0.1",
		"[2001:db8::1]:443":                 "2001:db8::1",
		"http://a.b/c?d=e":                  "a.b",
	}
	for in, want := range cases {
		if got := CleanServer(in); got != want {
			t.Errorf("CleanServer(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEnsurePorts(t *testing.T) {
	cfg := Config{Settings: DefaultSettings(), Points: []AccessPoint{
		{ID: "a", SocksPort: 1081},
		{ID: "b", SocksPort: 1081},
		{ID: "c", SocksPort: 1080},
		{ID: "d", SocksPort: 0},
	}}
	cfg.EnsurePorts()
	if cfg.Points[0].SocksPort != 1081 {
		t.Errorf("first point moved to %d", cfg.Points[0].SocksPort)
	}
	if cfg.Points[1].SocksPort == 1081 || cfg.Points[1].SocksPort == 1080 {
		t.Errorf("duplicate port kept: %d", cfg.Points[1].SocksPort)
	}
	if cfg.Points[2].SocksPort == 1080 {
		t.Errorf("a point kept the aggregate port")
	}
	if cfg.Points[3].SocksPort != 0 {
		t.Errorf("zero port became %d", cfg.Points[3].SocksPort)
	}
}

func TestNormalizeDefaults(t *testing.T) {
	cfg := Config{Points: []AccessPoint{{
		Server:   "https://vpn.example.edu.cn/",
		Username: " alice ",
	}}}
	cfg.Normalize()
	if cfg.Version != CurrentVersion {
		t.Errorf("version = %d", cfg.Version)
	}
	p := cfg.Points[0]
	if p.ID == "" || p.Port != 443 || p.Name != "vpn.example.edu.cn" {
		t.Errorf("point = %+v", p)
	}
	if p.Username != "alice" {
		t.Errorf("username = %q", p.Username)
	}
	if p.LoginDomain != "Radius" {
		t.Errorf("login domain = %q", p.LoginDomain)
	}
	if cfg.Settings.ListenHost != "127.0.0.1" || cfg.Settings.AggregatePort != 1080 {
		t.Errorf("settings = %+v", cfg.Settings)
	}
	if !cfg.Settings.AggregateEnabled {
		t.Error("a first-run config has the aggregate proxy off")
	}
}

func TestValidate(t *testing.T) {
	cfg := Config{Settings: DefaultSettings()}
	p := cfg.Add(AccessPoint{Server: "vpn.example.edu.cn", Username: "a"})
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	p.Server = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "服务器") {
		t.Errorf("empty server gave %v", err)
	}
}

func TestAddAssignsFreePort(t *testing.T) {
	cfg := Config{Settings: DefaultSettings()}
	first := cfg.Add(AccessPoint{Server: "a.example", Username: "u"})
	second := cfg.Add(AccessPoint{Server: "b.example", Username: "u"})
	if first.SocksPort == 0 || second.SocksPort == 0 || first.SocksPort == second.SocksPort {
		t.Errorf("ports = %d, %d", first.SocksPort, second.SocksPort)
	}
}

func TestRoutingLabels(t *testing.T) {
	for _, entry := range RoutingLabels {
		if !entry.Value.Valid() {
			t.Errorf("%q is not valid", entry.Value)
		}
		if entry.Value.Label() != entry.Label {
			t.Errorf("%q label = %q", entry.Value, entry.Value.Label())
		}
	}
	if Routing("nope").Valid() {
		t.Error("unknown routing is valid")
	}
}

func TestAuthModeDefaults(t *testing.T) {
	cfg := Config{Settings: DefaultSettings(), Points: []AccessPoint{{
		Server: "vpn.example.edu.cn", Username: "alice", InPool: true,
	}}}
	cfg.Normalize()
	if got := cfg.Points[0].AuthMode; got != string(AuthModeAuto) {
		t.Errorf("auth mode = %q", got)
	}
}

func TestWeComPointNeedsNoUsername(t *testing.T) {
	p := AccessPoint{
		Server: "vpn.example.edu.cn", Username: "",
		AuthMode: string(AuthModeWeCom), InPool: true,
	}
	p.Normalize()
	if err := p.Validate(); err != nil {
		t.Errorf("WeCom point: %v", err)
	}
	bad := AccessPoint{Server: "vpn.example.edu.cn", AuthMode: string(AuthModePassword), InPool: true}
	bad.Normalize()
	if err := bad.Validate(); err == nil {
		t.Error("password point without a username is valid")
	}
}

func TestAuthModeLabels(t *testing.T) {
	for _, entry := range AuthModeLabels {
		if !entry.Value.Valid() {
			t.Errorf("%q is not valid", entry.Value)
		}
		if entry.Value.Label() != entry.Label {
			t.Errorf("label of %q = %q", entry.Value, entry.Value.Label())
		}
	}
}

func TestParseAccessAddress(t *testing.T) {
	cases := []struct {
		in     string
		server string
		port   int
		bad    bool
	}{
		{"https://vpn.example.com:44892", "vpn.example.com", 44892, false},
		{"vpn.example.com:44892", "vpn.example.com", 44892, false},
		{"https://vpn.example.com", "vpn.example.com", 443, false},
		{"vpn.example.com", "vpn.example.com", 443, false},
		{"https://vpn.example.com:44892/portal?x=1", "vpn.example.com", 44892, false},
		{"http://host.example:8080", "host.example", 8080, false},
		{"https://[2001:db8::1]:44892", "2001:db8::1", 44892, false},
		{"https://host.example:bad", "", 0, true},
		{"", "", 0, true},
		{"ftp://host.example", "", 0, true},
	}
	for _, c := range cases {
		server, port, err := ParseAccessAddress(c.in)
		if c.bad {
			if err == nil {
				t.Errorf("ParseAccessAddress(%q) = %q, %d, want error", c.in, server, port)
			}
			continue
		}
		if err != nil || server != c.server || port != c.port {
			t.Errorf("ParseAccessAddress(%q) = %q, %d, %v; want %q, %d", c.in, server, port, err, c.server, c.port)
		}
	}
	if got := FormatAccessAddress("host.example", 443); got != "https://host.example" {
		t.Errorf("format 443 = %q", got)
	}
	if got := FormatAccessAddress("host.example", 44892); got != "https://host.example:44892" {
		t.Errorf("format = %q", got)
	}
	if got := FormatAccessAddress("2001:db8::1", 44892); got != "https://[2001:db8::1]:44892" {
		t.Errorf("format v6 = %q", got)
	}
}

func TestSecretStoreSetting(t *testing.T) {
	s := DefaultSettings()
	if s.SecretStore != SecretStoreFile {
		t.Errorf("default secret store = %q", s.SecretStore)
	}
	s.SecretStore = "bogus"
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.SecretStore != SecretStoreFile {
		t.Errorf("bogus normalized to %q", s.SecretStore)
	}
	s.SecretStore = SecretStoreKeychain
	if err := s.Validate(); err != nil || s.SecretStore != SecretStoreKeychain {
		t.Errorf("keychain kept? %q %v", s.SecretStore, err)
	}
}
