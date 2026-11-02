//go:build darwin

package main

import (
	"github.com/egoist/mygo"
)

// supportsDockToggle reports whether the Dock icon can be hidden here.
func supportsDockToggle() bool { return true }

// updateDockVisibility shows the Dock icon while the window is up, and hides
// it behind a menu bar icon once the window is closed, when the setting asks
// for that.
func (a *app) updateDockVisibility(hidden bool) {
	if hidden && a.cfg.Settings.HideDock {
		mygo.App.SetActivationPolicy(mygo.ActivationPolicyAccessory)
		a.setupTray()
		return
	}
	mygo.App.SetActivationPolicy(mygo.ActivationPolicyRegular)
	if a.tray != nil {
		a.tray.Destroy()
		a.tray = nil
	}
}

// setupTray adds the menu bar icon used while the Dock icon is hidden.
func (a *app) setupTray() {
	if a.tray != nil {
		return
	}
	icon := loadAppIconPNG()
	if len(icon) == 0 {
		return
	}
	tray, err := mygo.NewTray(mygo.TrayOptions{
		ID:             "main",
		Icon:           icon,
		IconIsTemplate: true,
		Menu: mygo.NewMenu([]*mygo.MenuItem{
			{Label: "显示窗口", Click: func(*mygo.MenuItem, *mygo.Window) { a.showWindow() }},
			mygo.Separator(),
			{Label: "退出", Click: func(*mygo.MenuItem, *mygo.Window) { a.quitFromTray() }},
		}),
	})
	if err != nil {
		return
	}
	tray.OnClick(a.showWindow)
	a.tray = tray
}
