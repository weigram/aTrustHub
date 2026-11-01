package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qy/easyconnect/internal/model"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	secrets, err := NewFileSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(dir, secrets)
	if err != nil {
		t.Fatal(err)
	}
	var id string
	if _, err := st.Update(func(cfg *model.Config) error {
		p := cfg.Add(model.AccessPoint{Server: "vpn.example.edu.cn", Username: "alice"})
		id = p.ID
		cfg.Settings.Routing = model.RoutingFailover
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetPassword(id, "s3cret"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetTOTP(id, "totp-test-value"); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	again, err := Open(dir, secrets)
	if err != nil {
		t.Fatal(err)
	}
	cfg := again.Config()
	if len(cfg.Points) != 1 || cfg.Points[0].ID != id {
		t.Fatalf("points = %+v", cfg.Points)
	}
	if cfg.Settings.Routing != model.RoutingFailover {
		t.Errorf("routing = %q", cfg.Settings.Routing)
	}
	if got, _ := again.Password(id); got != "s3cret" {
		t.Errorf("口令 = %q", got)
	}
	if got, _ := again.TOTP(id); got != "totp-test-value" {
		t.Errorf("totp = %q", got)
	}

	info, err := os.Stat(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("config mode = %o", mode)
	}
	info, err = os.Stat(filepath.Join(dir, "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("secrets mode = %o", mode)
	}
}

func TestFreshStore(t *testing.T) {
	st, err := Open(t.TempDir(), NewMemorySecrets())
	if err != nil {
		t.Fatal(err)
	}
	cfg := st.Config()
	if !cfg.Settings.AggregateEnabled {
		t.Error("aggregate proxy is off on a fresh store")
	}
	if len(cfg.Points) != 0 {
		t.Errorf("fresh store has %d points", len(cfg.Points))
	}
	if _, err := st.Password("nope"); !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("missing secret gave %v", err)
	}
}

func TestDeleteSecrets(t *testing.T) {
	st, err := Open(t.TempDir(), NewMemorySecrets())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetPassword("a", "p"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetTOTP("a", "t"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteSecrets("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Password("a"); !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("口令 survived: %v", err)
	}
}

type failingSecrets struct{}

func (failingSecrets) Get(string) (string, error) { return "", errors.New("no keychain") }
func (failingSecrets) Set(string, string) error   { return errors.New("no keychain") }
func (failingSecrets) Delete(string) error        { return errors.New("no keychain") }

func TestFallbackSecrets(t *testing.T) {
	fallback := NewMemorySecrets()
	both := FallbackSecrets{Primary: failingSecrets{}, Fallback: fallback}
	if err := both.Set("k", "v"); err != nil {
		t.Fatal(err)
	}
	if v, err := both.Get("k"); err != nil || v != "v" {
		t.Fatalf("Get = %q, %v", v, err)
	}

	// A working primary wins over what the fallback kept.
	primary := NewMemorySecrets()
	_ = primary.Set("k", "from-keychain")
	both = FallbackSecrets{Primary: primary, Fallback: fallback}
	if v, _ := both.Get("k"); v != "from-keychain" {
		t.Errorf("Get = %q", v)
	}
}

func TestRemovePoint(t *testing.T) {
	st, err := Open(t.TempDir(), NewMemorySecrets())
	if err != nil {
		t.Fatal(err)
	}
	var id string
	_, _ = st.Update(func(cfg *model.Config) error {
		id = cfg.Add(model.AccessPoint{Server: "vpn.example", Username: "a"}).ID
		return nil
	})
	if _, err := st.Update(func(cfg *model.Config) error {
		if !cfg.Remove(id) {
			t.Error("point did not exist")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(st.Config().Points) != 0 {
		t.Error("point survived removal")
	}
}

func TestAutoLoginIsOptInOnLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	old := `{"version":1,"settings":{"aggregateEnabled":true},"points":[
		{"id":"a","name":"A","autoConnect":true},
		{"id":"b","name":"B","autoConnect":true}]}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range cfg.Points {
		if p.AutoConnect {
			t.Errorf("%s still auto-connects", p.Name)
		}
	}
	// The cleared value is written back, so it stays off next launch.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"autoLoginOptIn": true`) {
		t.Errorf("migration not saved: %s", data)
	}

	// A later explicit choice survives the next load.
	cfg.Points[0].AutoConnect = true
	cfg.Settings.AutoLoginOptIn = true
	if err := saveJSON(path, cfg); err != nil {
		t.Fatal(err)
	}
	again, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Points[0].AutoConnect {
		t.Error("explicit auto-connect was cleared")
	}
}
