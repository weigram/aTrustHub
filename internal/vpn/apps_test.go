package vpn

import (
	"testing"

	atrustclient "github.com/mythologyli/zju-connect/client/atrust"
)

const appsJSON = `{
  "data": {
    "appList": {
      "data": {
        "appInfo": [
          {
            "name": "软件公司",
            "groupName": "默认分类",
            "apps": [
              {
                "id": "app-1",
                "name": "18F-同步通道（软件公司）",
                "description": "同步通道",
                "accessModel": "L3VPN",
                "subModel": "L3VPN",
                "groupName": "默认分类",
                "nodeGroupId": "node-1",
                "nodeGroupName": "Default",
                "iconPath": "/portal/preset_icon/a.png",
                "addressList": [
                  {"protocol": "tcp", "host": "10.18.12.89", "port": "1-65535"},
                  {"protocol": "udp", "host": "10.18.12.89", "port": "1-65535"}
                ]
              }
            ]
          },
          {
            "apps": [
              {
                "id": "app-2",
                "name": "部门管理系统",
                "accessModel": "TUN2WEB",
                "addressList": [{"protocol": "tcp", "host": "oa.example", "port": "443"}]
              }
            ]
          }
        ]
      }
    }
  }
}`

func TestParseApps(t *testing.T) {
	apps, err := atrustclient.ParseApps([]byte(appsJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 2 {
		t.Fatalf("apps = %d", len(apps))
	}
	a := apps[0]
	if a.Name != "18F-同步通道（软件公司）" || a.Description != "同步通道" {
		t.Errorf("app = %+v", a)
	}
	if len(a.Addresses) != 2 || a.Addresses[0].Protocol != "tcp" {
		t.Errorf("addresses = %+v", a.Addresses)
	}
	if apps[1].Name != "部门管理系统" || apps[1].AccessModel != "TUN2WEB" {
		t.Errorf("second = %+v", apps[1])
	}
}

func TestAppLabels(t *testing.T) {
	a := App{
		Name:        "18F-同步通道",
		AccessModel: "L3VPN",
		Addresses: []AppAddress{
			{Protocol: "tcp", Host: "10.18.12.89", Port: "1-65535"},
			{Protocol: "udp", Host: "10.18.12.89", Port: "1-65535"},
		},
	}
	if got := a.TypeLabel(); got != "隧道模式（TCP/UDP协议）" {
		t.Errorf("type = %q", got)
	}
	lines := a.AddressLines()
	if len(lines) != 2 || lines[0] != "tcp 10.18.12.89:1-65535" {
		t.Errorf("lines = %v", lines)
	}
	if got := a.AddressSummary(); got != "tcp 10.18.12.89:1-65535 等 2 条" {
		t.Errorf("summary = %q", got)
	}
	if got := (App{AccessModel: "WEB"}).TypeLabel(); got != "Web 模式" {
		t.Errorf("web type = %q", got)
	}
}

func TestAppsFromZJU(t *testing.T) {
	in := []atrustclient.App{{
		ID: "x", Name: "n", AccessModel: "L3VPN",
		Addresses: []atrustclient.AppAddress{{Protocol: "tcp", Host: "h", Port: "80"}},
	}}
	out := appsFromZJU(in)
	if len(out) != 1 || out[0].Name != "n" || len(out[0].Addresses) != 1 {
		t.Errorf("out = %+v", out)
	}
}

func TestAppTestPorts(t *testing.T) {
	a := App{Addresses: []AppAddress{{Protocol: "all", Host: "10.20.163.37", Port: "1-65535"}}}
	if a.Host() != "10.20.163.37" {
		t.Errorf("host = %q", a.Host())
	}
	ports := a.TestPorts()
	if len(ports) == 0 || ports[0] != 443 {
		t.Errorf("ports = %v", ports)
	}
	b := App{Addresses: []AppAddress{{Host: "h", Port: "8443"}}}
	if got := b.TestPorts(); len(got) != 1 || got[0] != 8443 {
		t.Errorf("single port = %v", got)
	}
	c := App{Addresses: []AppAddress{{Host: "h", Port: "8000-8010"}}}
	if got := c.TestPorts(); len(got) != 1 || got[0] != 8000 {
		t.Errorf("narrow range = %v", got)
	}
}

func TestAppHosts(t *testing.T) {
	a := App{Addresses: []AppAddress{
		{Host: "10.0.0.1", Port: "1-65535"},
		{Host: "10.0.0.2", Port: "1-65535"},
		{Host: "10.0.0.1", Port: "1-65535"},
	}}
	hosts := a.Hosts()
	if len(hosts) != 2 || hosts[0] != "10.0.0.1" || hosts[1] != "10.0.0.2" {
		t.Errorf("hosts = %v", hosts)
	}
	if got := a.PortsAt(1); len(got) == 0 || got[0] != 443 {
		t.Errorf("portsAt = %v", got)
	}
}

func TestExpandHostRange(t *testing.T) {
	got := expandHostRange("10.20.162.68-10.20.162.69")
	if len(got) != 2 || got[0] != "10.20.162.68" || got[1] != "10.20.162.69" {
		t.Errorf("range = %v", got)
	}
	if ips := (App{Addresses: []AppAddress{{Host: "10.0.0.1-10.0.0.3", Port: "1-65535"}}}).ProbeHosts(); len(ips) != 3 {
		t.Errorf("probe hosts = %v", ips)
	}
	cidr := expandHostRange("192.168.38.0/30")
	if len(cidr) != 4 {
		t.Errorf("cidr = %v", cidr)
	}
	if single := expandHostRange("10.0.0.9"); len(single) != 1 || single[0] != "10.0.0.9" {
		t.Errorf("single = %v", single)
	}
}
