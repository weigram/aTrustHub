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

// DNS 自检只能问域名：应用地址列表里还有 192.168.168.0/24 这类网段，
// 拿去解析必然失败，会让守卫误判成「DNS 挂了」。
func TestIsProbeName(t *testing.T) {
	good := []string{"gitlab.qctc.com.cn", "access.qctc.com.cn", "a.b"}
	bad := []string{"", "192.168.168.0/24", "10.18.11.3", "10.20.168.68:5237", "1-65535"}
	for _, n := range good {
		if !isProbeName(n) {
			t.Errorf("%q 应当可以用于探测", n)
		}
	}
	for _, n := range bad {
		if isProbeName(n) {
			t.Errorf("%q 不应当用于探测", n)
		}
	}
}

// 隧道保活：连续两次探测失败才算死，成功一次就清零。
func TestKeepAliveCounts(t *testing.T) {
	var k tunKeepAlive
	if k.result("p", false) {
		t.Fatal("第一次失败不该判定为死")
	}
	if !k.result("p", false) {
		t.Fatal("连续两次失败应当判定为死")
	}
	// 判定之后计数清零，再失败一次不能说死。
	if k.result("p", false) {
		t.Fatal("判定后计数应当清零")
	}
	k.result("p", false)
	if k.result("p", true) {
		t.Fatal("成功不该触发重建")
	}
	if k.result("p", false) {
		t.Fatal("成功之后计数应当清零")
	}
}

// 系统代理只在统一入口确实在监听时才允许存在：TUN 接管或端口死了都必须关掉，
// 否则整机断网。
func TestSystemProxyGuards(t *testing.T) {
	// 单元测试不能碰真实系统设置：CI 上会卡在管理员密码弹窗。
	orig := applySystemProxyFn
	applySystemProxyFn = func(string, bool) error { return nil }
	t.Cleanup(func() { applySystemProxyFn = orig })

	a := testApp(t)

	// TUN 开启时，开关不接受打开。
	a.tunOn = true
	a.sysProxyOn = false
	a.sysProxySwitch = true
	a.toggleSystemProxy()
	if a.sysProxySwitch {
		t.Error("TUN 开启时不应允许打开系统代理")
	}

	// 统一入口没在监听时，也不允许打开。
	a.tunOn = false
	a.sysProxySwitch = true
	a.toggleSystemProxy()
	if a.sysProxySwitch {
		t.Error("统一入口未监听时不应允许打开系统代理")
	}

	// 已经开着但监听没了：守卫要把它关掉。
	a.sysProxyOn = true
	a.guardSystemProxy()
	if a.sysProxyOn {
		t.Error("统一入口停止后应当自动关闭系统代理")
	}
}

// 退出清理必须清掉控制文件并把 tunOn 复位，否则下次启动以为 TUN 还在。
func TestTeardownTUNOnExit(t *testing.T) {
	a := testApp(t)
	a.tunOn = true
	a.tunPID = 0

	files := []string{"tun.stop", "tun.pid", "tun.reload", "tun.probe", "tun.probe.result"}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(a.dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	a.teardownTUNOnExit()

	if a.tunOn {
		t.Error("退出后 tunOn 应当复位")
	}
	for _, name := range files {
		if _, err := os.Stat(filepath.Join(a.dir, name)); err == nil {
			t.Errorf("退出后 %s 应当被删除", name)
		}
	}
}
