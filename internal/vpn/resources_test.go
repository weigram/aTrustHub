package vpn

import (
	"net"
	"testing"

	zcclient "github.com/mythologyli/zju-connect/client"
)

func TestDropDisabledApps(t *testing.T) {
	ips := []zcclient.IPResource{
		{IPMin: net.IPv4(10, 18, 1, 1), AppID: "a"},
		{IPMin: net.IPv4(192, 168, 6, 11), AppID: "b"},
		{IPMin: net.IPv4(10, 20, 1, 1), AppID: "c"},
	}
	domains := zcclient.DomainResources{
		"i6s.qctc.com.cn": {{AppID: "a"}},
		"gitlab.qctc.com.cn": {{AppID: "b"}},
		"only-b": {{AppID: "b"}, {AppID: "b"}},
	}
	gotIP, gotDomain := dropDisabledApps([]string{"b"}, ips, domains)
	if len(gotIP) != 2 {
		t.Fatalf("IP 资源应剩 2 条，实际 %d", len(gotIP))
	}
	for _, r := range gotIP {
		if r.AppID == "b" {
			t.Fatal("停用的应用仍在 IP 资源里")
		}
	}
	if _, ok := gotDomain["gitlab.qctc.com.cn"]; ok {
		t.Fatal("整个应用被停用时，域名应完全不再注册")
	}
	if _, ok := gotDomain["i6s.qctc.com.cn"]; !ok {
		t.Fatal("未停用的域名被误删")
	}
	// 空列表必须原样返回，避免影响正常路径。
	sameIP, sameDomain := dropDisabledApps(nil, ips, domains)
	if len(sameIP) != len(ips) || len(sameDomain) != len(domains) {
		t.Fatal("没有停用项时资源被改动了")
	}
}
