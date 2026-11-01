package main

import "testing"

func TestShQuote(t *testing.T) {
	if got := shQuote("a b"); got != "'a b'" {
		t.Errorf("got %q", got)
	}
	if got := shQuote("it's"); got != `'it'\''s'` {
		t.Errorf("got %q", got)
	}
}
