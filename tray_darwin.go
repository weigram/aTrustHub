//go:build darwin

package main

import (
	"github.com/egoist/mygo"
)

// supportsDockToggle reports whether the Dock icon can be hidden here.
func supportsDockToggle() bool { return true }

// applyDockPolicy shows or hides the Dock icon to match the setting.
func (a *app) applyDockPolicy() {
	if a.cfg.Settings.HideDock {
		mygo.App.SetActivationPolicy(mygo.ActivationPolicyAccessory)
		return
	}
	mygo.App.SetActivationPolicy(mygo.ActivationPolicyRegular)
	// The menu bar icon is only a replacement for the Dock icon.
	if a.tray != nil {
		a.tray.Destroy()
		a.tray = nil
	}
}

// setupTray adds a menu bar icon when the app has no Dock icon, so it can
// still be reopened or quit.
func (a *app) setupTray() {
	if !a.cfg.Settings.HideDock {
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
