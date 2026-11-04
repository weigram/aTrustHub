package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/qy/easyconnect/internal/model"
)

// 应用启停与 TUN 开关都必须落盘：store.Update 只改内存，
// 忘了 Save 就会「重启后全部还原」。
func TestToggleStateReachesDisk(t *testing.T) {
	a := testApp(t)
	var id string
	if _, err := a.store.Update(func(cfg *model.Config) error {
		p := cfg.Add(model.AccessPoint{Name: "落盘点", Server: "vpn.example.edu.cn", AuthMode: string(model.AuthModePassword)})
		id = p.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.saveConfig(); err != nil {
		t.Fatal(err)
	}

	a.setAppEnabled(id, "app1", false)
	a.persistTunState(true, id)

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
		t.Fatalf("停用没有落盘：%+v", p)
	}
	if !disk.Settings.TunEnabled || disk.Settings.TunPointID != id {
		t.Fatalf("TUN 状态没有落盘：%+v", disk.Settings)
	}
}
