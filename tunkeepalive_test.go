package main

import (
	"testing"
	"time"
)

func TestTunKeepAliveRebuildsAfterTwoFailures(t *testing.T) {
	var k tunKeepAlive
	if k.result("a", false) {
		t.Fatal("one failed probe must not rebuild the tunnel")
	}
	if got := k.failsFor("a"); got != 1 {
		t.Fatalf("fails = %d, want 1", got)
	}
	if !k.result("a", false) {
		t.Fatal("the second failed probe must ask for a rebuild")
	}
	if got := k.failsFor("a"); got != 0 {
		t.Fatalf("fails = %d, want reset after a rebuild", got)
	}
	if k.result("a", true) {
		t.Fatal("a successful probe must never rebuild")
	}
	if k.result("b", false) {
		t.Fatal("the first failure of another point must not rebuild")
	}
	if !k.result("b", false) {
		t.Fatal("failures must be counted per access point")
	}
	k.reset()
	if got := k.failsFor("b"); got != 0 {
		t.Fatalf("fails after reset = %d, want 0", got)
	}
}

func TestTunKeepAliveProbesAtMostEvery90s(t *testing.T) {
	var k tunKeepAlive
	now := time.Now()
	if !k.shouldRun(now) {
		t.Fatal("first probe should run")
	}
	if k.shouldRun(now.Add(30 * time.Second)) {
		t.Fatal("a second probe inside the interval must wait")
	}
	if !k.shouldRun(now.Add(2 * time.Minute)) {
		t.Fatal("the probe must run again after the interval")
	}
}
