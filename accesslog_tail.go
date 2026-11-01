package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/qy/easyconnect/internal/vpn"
)

// accessRecord is one line the TUN helper writes to the access log.
type accessRecord struct {
	Time   int64  `json:"t"`
	Point  string `json:"point"`
	Target string `json:"target"`
	Port   int    `json:"port"`
	OK     bool   `json:"ok"`
}

// accessLogPath is where the TUN helper appends its access records.
func (a *app) accessLogPath() string {
	return filepath.Join(a.dir, "tun-access.log")
}

// tailAccessLog follows the helper's access log and republishes each record as
// a regular access-log entry, so the access log keeps working in TUN mode.
func (a *app) tailAccessLog() {
	var offset int64
	var lastSize int64 = -1
	for {
		time.Sleep(time.Second)
		path := a.accessLogPath()
		st, err := os.Stat(path)
		if err != nil {
			continue
		}
		// A new TUN session truncates the file: start over.
		if st.Size() < lastSize {
			offset = 0
		}
		lastSize = st.Size()
		if st.Size() == offset {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			continue
		}
		r := bufio.NewReader(f)
		for {
			line, err := r.ReadString('\n')
			if len(line) > 0 {
				offset += int64(len(line))
				line = line[:len(line)-1]
				var rec accessRecord
				if json.Unmarshal([]byte(line), &rec) == nil {
					a.publishAccess(rec)
				}
			}
			if err != nil {
				break
			}
		}
		f.Close()
	}
}

// publishAccess turns one helper record into an access-log line.
func (a *app) publishAccess(rec accessRecord) {
	target := rec.Target
	if rec.Port > 0 {
		target = fmt.Sprintf("%s:%d", rec.Target, rec.Port)
	}
	appName := a.appNameForHost(rec.Target)
	plain := fmt.Sprintf("%s → %s", target, rec.Point)
	plainFail := fmt.Sprintf("%s ｜ %s", target, rec.Point)
	if appName != "" {
		// Drop the variant logged before the app list was known.
		a.bus.Drop(vpn.AccessOK, plain)
		a.bus.Drop(vpn.AccessFail, plainFail)
	}
	if rec.OK {
		if appName != "" {
			a.bus.Upsert(vpn.AccessOK, fmt.Sprintf("%s → %s ｜ 应用：%s", target, rec.Point, appName))
			return
		}
		a.bus.Upsert(vpn.AccessOK, fmt.Sprintf("%s → %s", target, rec.Point))
		return
	}
	if appName != "" {
		a.bus.Upsert(vpn.AccessFail, fmt.Sprintf("%s ｜ %s ｜ 应用：%s", target, rec.Point, appName))
		return
	}
	a.bus.Upsert(vpn.AccessFail, fmt.Sprintf("%s ｜ %s", target, rec.Point))
}

// appNameForHost finds the application of an online access point that owns
// host, so the access log can name it.
func (a *app) appNameForHost(host string) string {
	if host == "" {
		return ""
	}
	for _, v := range a.mgr.Views() {
		if v.State != vpn.StateOnline {
			continue
		}
		for _, app := range v.Apps {
			if app.Covers(host) {
				return app.Name
			}
		}
	}
	return ""
}
