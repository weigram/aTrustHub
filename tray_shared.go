package main

import (
	"os"
	"path/filepath"
	"time"

	"github.com/egoist/mygo"
)

// showWindow brings the main window back from the tray or menu bar, and puts
// the Dock icon back on macOS.
func (a *app) showWindow() {
	if a.win == nil || a.win.IsDestroyed() {
		a.tunLogf("showWindow: 重建主窗口")
		a.createWindow()
	}
	a.updateDockVisibility(false)
	a.win.Show()
	a.win.Focus()
	// A window that was hidden needs a fresh frame: the clickable regions of
	// an immediate-mode UI come from the last frame, and hiding may leave them
	// empty, which makes every click look ignored.
	a.win.Invalidate()
	go func() {
		time.Sleep(120 * time.Millisecond)
		if a.win != nil {
			a.win.Invalidate()
		}
	}()
}

// quitFromTray quits for real, instead of hiding the window.
func (a *app) quitFromTray() { a.askQuit() }

// askQuit opens the confirmation instead of closing the app at once.
func (a *app) askQuit() {
	if a.win != nil {
		a.showWindow()
	}
	a.win.Update(func() { a.quitAsk = true })
	a.invalidate()
}

// doQuit really ends the process.
func (a *app) doQuit() {
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
