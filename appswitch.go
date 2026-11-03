package main

import (
	"fmt"

	"github.com/qy/easyconnect/internal/model"
)

// appEnabled reports whether one application's addresses may enter the tunnel.
func (a *app) appEnabled(pointID, appID string) bool {
	p := a.cfg.Find(pointID)
	if p == nil {
		return true
	}
	return !p.AppDisabled(appID)
}

// setAppEnabled stores the choice. The global TUN picks it up by itself within
// a few seconds; the access point's own SOCKS tunnel reads its resource list
// when it logs in, so it needs a reconnect to follow.
func (a *app) setAppEnabled(pointID, appID string, enabled bool) {
	var name, appName string
	changed := false
	_, err := a.store.Update(func(cfg *model.Config) error {
		p := cfg.Find(pointID)
		if p == nil {
			return fmt.Errorf("找不到这个接入点")
		}
		if !p.SetAppDisabled(appID, !enabled) {
			return nil
		}
		changed = true
		name = p.Name
		appName = a.appName(pointID, appID)
		return nil
	})
	if err != nil {
		a.toast = "保存失败：" + err.Error()
		return
	}
	a.cfg = a.store.Config()
	if !changed {
		return
	}
	if a.tunOn {
		a.win.Update(func() {
			// An empty snapshot is what the refresh path reads as "rebuild me".
			a.tunPoints = ""
			a.tunMirror()
		})
	}
	if enabled {
		a.toast = fmt.Sprintf("已恢复「%s」的隧道代理（%s），全局 TUN 稍后自动更新", appName, name)
	} else {
		a.toast = fmt.Sprintf("已停用「%s」的隧道代理（%s）：它的地址不再进隧道；该接入点重新登录后其独立 SOCKS 通道同步生效", appName, name)
	}
	a.invalidate()
}

// appName looks up a display name for a toast, falling back to the ID.
func (a *app) appName(pointID, appID string) string {
	for _, entry := range a.allApps() {
		if entry.PointID == pointID && entry.App.ID == appID {
			return entry.App.Name
		}
	}
	return appID
}
