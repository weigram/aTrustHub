package main

import "testing"

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
