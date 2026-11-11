package auth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// A desktop login runs without a console, so stdin cannot supply the SMS
// code the gateway asks for.
func TestSMSCheckCodeWithoutConsole(t *testing.T) {
	defer stdinWithoutConsole(t)()

	posted := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		posted <- r.PostFormValue("code")
		w.Write([]byte(`{"code":0,"data":{"nextService":""}}`))
	}))
	defer srv.Close()

	var asked CodeRequest
	s := &Session{client: srv.Client(), baseURL: srv.URL}
	s.promptCode = func(req CodeRequest) (string, error) {
		asked = req
		return "654321", nil
	}
	if _, err := s.smsCheckCode(authStep{SMSMode: smsWithoutAuthID}); err != nil {
		t.Fatalf("login died at the SMS prompt: %v", err)
	}
	if asked.Kind != CodeSMS {
		t.Errorf("prompter asked for kind %d, want %d", asked.Kind, CodeSMS)
	}
	if got := <-posted; got != "654321" {
		t.Fatalf("gateway got code %q, want 654321", got)
	}
}

// The prompt carries what the server said when it sent the SMS.
func TestSMSAskCarriesTip(t *testing.T) {
	tip := "验证码已发送到您的手机：138****0000, 请查收！"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"code":0,"message":"发送成功","data":{"tips":"` + tip + `"}}`))
	}))
	defer srv.Close()

	var asked CodeRequest
	s := &Session{client: srv.Client(), baseURL: srv.URL}
	s.promptCode = func(req CodeRequest) (string, error) {
		asked = req
		return "654321", nil
	}
	if err := s.authSms(authStep{SMSMode: smsWithoutAuthID}); err != nil {
		t.Fatalf("authSms: %v", err)
	}
	if _, err := s.smsCheckCode(authStep{SMSMode: smsWithoutAuthID}); err != nil {
		t.Fatalf("login died at the SMS prompt: %v", err)
	}
	if want := "发送成功: " + tip; asked.Tip != want {
		t.Errorf("prompter tip = %q, want %q", asked.Tip, want)
	}
}

func stdinWithoutConsole(t *testing.T) func() {
	t.Helper()
	original := os.Stdin
	f, err := os.OpenFile(filepath.Join(t.TempDir(), "stdin"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = f
	return func() {
		os.Stdin = original
		_ = f.Close()
	}
}
