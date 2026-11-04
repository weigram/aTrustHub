package main

import (
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
