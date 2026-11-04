package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/vpn"
)

// 点真实卡片上的开关，磁盘上的配置必须跟着变；这正对应用户的
// 「关掉应用 → 退出 → 重开又全部启用」。
func TestAppCardSwitchWritesDisk(t *testing.T) {
	a := testApp(t)
	var id string
	if _, err := a.store.Update(func(cfg *model.Config) error {
		p := cfg.Add(model.AccessPoint{Name: "卡片点", Server: "vpn.example.edu.cn", AuthMode: string(model.AuthModePassword), InPool: true})
		id = p.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.saveConfig(); err != nil {
		t.Fatal(err)
	}

	entry := appEntry{PointID: id, PointName: "卡片点", App: vpn.App{ID: "app1", Name: "测试应用"}}
	tt := ui.NewTester(func(c *ui.Context) {
		ui.Column(c).Padding(10).Children(func() { a.appCard(c, entry) })
	}, 900, 300)
	tt.Frame()
	if err := tt.Click("隧道代理 测试应用"); err != nil {
		t.Fatalf("click switch: %v", err)
	}
	tt.Frame()

	raw, err := os.ReadFile(filepath.Join(a.dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var disk model.Config
	if err := json.Unmarshal(raw, &disk); err != nil {
		t.Fatal(err)
	}
	p := disk.Find(id)
	if p == nil || !p.AppDisabled("app1") {
		t.Fatalf("点击后磁盘上没有停用记录：%+v", p)
	}
}
