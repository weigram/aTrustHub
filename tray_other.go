//go:build !windows

package main

// setupTray is a no-op outside Windows, where closing the window quits.
func (a *app) setupTray() {}
