package main

import (
	"os"
	"path/filepath"

	"github.com/egoist/mygo"
)

// showWindow brings the main window back from the tray or menu bar.
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
