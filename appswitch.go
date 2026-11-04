package main

import (
	"fmt"
	"sort"

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
	if !changed {
		a.cfg = a.store.Config()
		return
	}
	// Update 只改内存：落盘必须显式 Save，否则重启就回到旧状态。
	if err := a.saveConfig(); err != nil {
		a.toast = "保存失败：" + err.Error()
		return
	}
	if a.appSwitch != nil {
		delete(a.appSwitch, pointID+"/"+appID)
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

// setAllAppsEnabled turns the tunnel proxy on or off for every application of
// one access point at once, which is what the two buttons on its card do.
func (a *app) setAllAppsEnabled(pointID string, enabled bool) {
	var name string
	count := 0
	ids := make([]string, 0, 8)
	_, err := a.store.Update(func(cfg *model.Config) error {
		p := cfg.Find(pointID)
		if p == nil {
			return fmt.Errorf("找不到这个接入点")
		}
		name = p.Name
		ids = a.appIDs(pointID)
		if enabled {
			count = len(p.DisabledApps)
			p.DisabledApps = nil
			return nil
		}
		disabled := make([]string, 0, len(ids))
		for _, id := range ids {
			if !p.AppDisabled(id) {
				disabled = append(disabled, id)
			}
		}
		count = len(disabled)
		sort.Strings(disabled)
		p.DisabledApps = disabled
		return nil
	})
	if err != nil {
		a.toast = "保存失败：" + err.Error()
		return
	}
	// Update 只改内存：落盘必须显式 Save，否则重启后停用记录全部丢失。
	if err := a.saveConfig(); err != nil {
		a.toast = "保存失败：" + err.Error()
		return
	}
	// 批量改了状态，让每个开关按记录重建。
	a.appSwitch = map[string]*bool{}
	if a.tunOn {
		a.win.Update(func() {
			a.tunPoints = ""
			a.tunMirror()
		})
	}
	if enabled {
		a.toast = fmt.Sprintf("已启用「%s」的全部应用隧道代理（%d 个已恢复）", name, count)
	} else {
		a.toast = fmt.Sprintf("已停用「%s」的全部应用隧道代理（%d 个）", name, count)
	}
	a.invalidate()
}

// appIDs lists the application identifiers the point published.
func (a *app) appIDs(pointID string) []string {
	ids := make([]string, 0, 8)
	for _, entry := range a.allApps() {
		if entry.PointID != pointID {
			continue
		}
		if entry.App.ID != "" {
			ids = append(ids, entry.App.ID)
		}
	}
	return ids
}
