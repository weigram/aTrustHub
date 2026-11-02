//go:build !windows && !darwin

package main

// setupTray is a no-op on platforms without a tray.
func (a *app) setupTray() {}

// supportsDockToggle reports whether the Dock icon can be hidden here.
func supportsDockToggle() bool { return false }

// applyDockPolicy does nothing outside macOS.
func (a *app) applyDockPolicy() {}
