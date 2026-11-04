package main

import (
	"github.com/qy/easyconnect/internal/vpn"
	"os"
	"path/filepath"
	"testing"
)

// The helper must be found from a development build directory, which is where
// "resources/<goos>-<goarch>/" holds it.
func TestMultitunPathFindsDevBuild(t *testing.T) {
	dir := t.TempDir()
	want := filepath.Join(dir, "resources", "zju-connect-multitun"+helperSuffix)
	if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(want, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	wd, _ := os.Getwd()
	defer func() { _ = os.Chdir(wd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	got, _ := multitunPath()
	if st, err := os.Stat(got); err != nil || st.IsDir() {
		t.Fatalf("multitunPath() = %q，该文件不存在", got)
	}
}

// A missing helper must come back with the list of places that were tried.
func TestMultitunPathReportsTried(t *testing.T) {
	dir := t.TempDir()
	wd, _ := os.Getwd()
	defer func() { _ = os.Chdir(wd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	_, tried := multitunPath()
	if tried == "" {
		t.Fatal("找不到 helper 时应给出已尝试的路径")
	}
}

// 记住的开关位置要落在正确的接入点上：优先上次那个，不在线才用第一个在线的。
func TestPickResumePoint(t *testing.T) {
	views := []vpn.View{
		{ID: "a", State: vpn.StateOnline},
		{ID: "b", State: vpn.StateOffline},
	}
	if got := pickResumePoint("a", views); got != "a" {
		t.Errorf("首选在线项：got %q", got)
	}
	if got := pickResumePoint("b", views); got != "a" {
		t.Errorf("记住的不在线时用第一个在线项：got %q", got)
	}
	if got := pickResumePoint("", nil); got != "" {
		t.Errorf("没有在线项应返回空：got %q", got)
	}
}
