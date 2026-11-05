package main

import (
	"errors"
	"strings"
	"testing"
)

func TestVersionGreater(t *testing.T) {
	cases := []struct {
		newest, current string
		want            bool
	}{
		{"0.25.0", "0.24.3", true},
		{"0.24.3", "0.24.3", false},
		{"0.24.2", "0.24.3", false},
		{"1.0.0", "0.24.3", true},
		{"0.25", "0.24.9", true},
		{"0.10.0", "0.9.0", true},
		{"v0.11.0", "0.10.9", true},
	}
	for _, c := range cases {
		if got := versionGreater(c.newest, c.current); got != c.want {
			t.Errorf("versionGreater(%q,%q)=%v want %v", c.newest, c.current, got, c.want)
		}
	}
}

func TestParseRelease(t *testing.T) {
	info, err := parseRelease(`{"tag_name":"v0.25.0","html_url":"https://github.com/x/y/releases/tag/v0.25.0","body":"第一行\n第二行"}`, "https://api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "0.25.0" || info.URL == "" || info.Notes != "第一行" {
		t.Fatalf("%+v", info)
	}
	if _, err := parseRelease(`{"tag_name":""}`, "u"); err == nil {
		t.Fatal("空版本号应报错")
	}
}

func TestParseManifest(t *testing.T) {
	info, err := parseManifest(`{"name":"aTrustHub","version":"0.24.3"}`, "https://cdn.jsdelivr.net")
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "0.24.3" || info.URL != projectURL+"/releases/tag/v0.24.3" {
		t.Fatalf("%+v", info)
	}
	if _, err := parseManifest(`{}`, "u"); err == nil {
		t.Fatal("缺版本号应报错")
	}
}

// GitHub 打不开时，图标和下载链接都要走镜像，否则点了是白屏。
func TestGitHubPageUsesMirror(t *testing.T) {
	a := testApp(t)
	a.ghReachable = true
	if got := a.githubPage("https://github.com/x/y"); got != "https://github.com/x/y" {
		t.Errorf("直连可用时不该改地址，得到 %s", got)
	}

	a.ghReachable = false
	want := ghMirrorPrefix + "https://github.com/x/y"
	if got := a.githubPage("https://github.com/x/y"); got != want {
		t.Errorf("直连不可用时应走镜像，得到 %s，期望 %s", got, want)
	}
}

// 镜像地址本身要能被 gh-proxy 正确代理：前缀 + 完整地址。
func TestMirrorPrefixFormat(t *testing.T) {
	if !strings.HasSuffix(ghMirrorPrefix, "/") {
		t.Fatal("镜像前缀应以 / 结尾，才能直接拼接完整地址")
	}
	if !strings.HasPrefix(ghMirrorPrefix, "https://") {
		t.Fatal("镜像前缀应是 https")
	}
}

// 启动时 DNS 还没通，请求会在解析阶段就失败——这不代表 GitHub 被封。
func TestIsResolveError(t *testing.T) {
	yes := []string{
		`Get "https://api.github.com/x": dial tcp: lookup api.github.com: no such host`,
		`lookup gh-proxy.com: no such host`,
		`server misbehaving`,
	}
	no := []string{
		`Get "https://api.github.com/x": dial tcp 1.2.3.4:443: i/o timeout`,
		`HTTP 403`,
		`connection refused`,
	}
	for _, m := range yes {
		if !isResolveError(errors.New(m)) {
			t.Errorf("应当识别为解析失败：%s", m)
		}
	}
	for _, m := range no {
		if isResolveError(errors.New(m)) {
			t.Errorf("不该识别为解析失败：%s", m)
		}
	}
}
