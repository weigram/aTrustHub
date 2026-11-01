package main

import (
	"net/url"
	"strings"
)

// isQyWechatLoginURL reports whether loginURL is WeCom's QR page, whose
// QR status the app can poll from Go so a stuck page still finishes.
func isQyWechatLoginURL(loginURL string) bool {
	u, err := url.Parse(loginURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	path := strings.ToLower(u.Path)
	return (host == "open.work.weixin.qq.com" || host == "qyapi.weixin.qq.com") &&
		strings.Contains(path, "qrconnect")
}
