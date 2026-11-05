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

// 停用所有必须把全部应用写进停用列表：只写「新停用的」会让原先已停用的
// 应用掉出列表，重启后重新变成启用。
func TestBulkDisabledCoversEverything(t *testing.T) {
	ids := []string{"a", "b", "c"}

	off := bulkDisabled(ids, false)
	if len(off) != 3 {
		t.Fatalf("停用所有应包含全部应用，得到 %v", off)
	}
	for _, want := range ids {
		found := false
		for _, got := range off {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("缺少 %s：%v", want, off)
		}
	}

	if on := bulkDisabled(ids, true); on != nil {
		t.Fatalf("启用所有应清空列表，得到 %v", on)
	}
}
