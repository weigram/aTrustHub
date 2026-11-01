//go:build windows

package main

import (
	"os"
	"path/filepath"

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

// showWindow brings the main window back from the tray.
func (a *app) showWindow() {
	if a.win == nil {
		return
	}
	a.win.Show()
	a.win.Focus()
}

// quitFromTray quits for real, instead of hiding the window.
func (a *app) quitFromTray() {
	a.quitRequested = true
	mygo.App.Quit()
}

// loadAppIconPNG returns the tray icon bytes.
func loadAppIconPNG() []byte {
	var paths []string
	if dir, err := mygo.App.Path(mygo.PathResources); err == nil && dir != "" {
		paths = append(paths, filepath.Join(dir, "icon.png"))
	}
	paths = append(paths, filepath.Join("resources", "icon.png"))
	for _, path := range paths {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			return data
		}
	}
	return nil
}
