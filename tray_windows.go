//go:build windows

package main

import (
	"github.com/egoist/mygo"
)

// setupTray adds the notification-area icon, so closing the window keeps the
// app (and its tunnels) running.
func (a *app) setupTray() {
	icon := loadAppIconPNG()
	if len(icon) == 0 {
		return
	}
	tray, err := mygo.NewTray(mygo.TrayOptions{
		ID:    "main",
		Icon:  icon,
		Title: "aTrust Hub",
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

// supportsDockToggle reports whether the Dock icon can be hidden here.
func supportsDockToggle() bool { return false }

// applyDockPolicy does nothing on Windows.
func (a *app) applyDockPolicy() {}
