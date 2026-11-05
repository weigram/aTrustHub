package main

import (
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
