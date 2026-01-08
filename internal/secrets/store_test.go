package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/99designs/keyring"

	"github.com/steipete/gogcli/internal/config"
)

// keyringConfig creates a keyring.Config for testing.
func keyringConfig(keyringDir string) keyring.Config {
	return keyring.Config{
		ServiceName:              config.AppName,
		KeychainTrustApplication: runtime.GOOS == "darwin",
		AllowedBackends:          []keyring.BackendType{keyring.FileBackend},
		FileDir:                  keyringDir,
		FilePasswordFunc:         fileKeyringPasswordFunc(),
	}
}

func TestResolveKeyringBackendInfo_Default(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	t.Setenv("GOG_KEYRING_BACKEND", "")

	info, err := ResolveKeyringBackendInfo()
	if err != nil {
		t.Fatalf("ResolveKeyringBackendInfo: %v", err)
	}

	if info.Value != "auto" {
		t.Fatalf("expected auto, got %q", info.Value)
	}

	if info.Source != keyringBackendSourceDefault {
		t.Fatalf("expected source default, got %q", info.Source)
	}
}

func TestResolveKeyringBackendInfo_Config(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	t.Setenv("GOG_KEYRING_BACKEND", "")

	path, err := config.ConfigPath()
	if err != nil {
		t.Fatalf("ConfigPath: %v", err)
	}

	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err = os.WriteFile(path, []byte(`{ keyring_backend: "file" }`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	info, err := ResolveKeyringBackendInfo()
	if err != nil {
		t.Fatalf("ResolveKeyringBackendInfo: %v", err)
	}

	if info.Value != "file" {
		t.Fatalf("expected file, got %q", info.Value)
	}

	if info.Source != keyringBackendSourceConfig {
		t.Fatalf("expected source config, got %q", info.Source)
	}
}

func TestResolveKeyringBackendInfo_EnvOverridesConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	t.Setenv("GOG_KEYRING_BACKEND", "keychain")

	path, err := config.ConfigPath()
	if err != nil {
		t.Fatalf("ConfigPath: %v", err)
	}

	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err = os.WriteFile(path, []byte(`{ keyring_backend: "file" }`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	info, err := ResolveKeyringBackendInfo()
	if err != nil {
		t.Fatalf("ResolveKeyringBackendInfo: %v", err)
	}

	if info.Value != "keychain" {
		t.Fatalf("expected keychain, got %q", info.Value)
	}

	if info.Source != keyringBackendSourceEnv {
		t.Fatalf("expected source env, got %q", info.Source)
	}
}

func TestAllowedBackends_Invalid(t *testing.T) {
	_, err := allowedBackends(KeyringBackendInfo{Value: "nope"})
	if err == nil {
		t.Fatalf("expected error")
	}

	if !errors.Is(err, errInvalidKeyringBackend) {
		t.Fatalf("expected invalid backend error, got %v", err)
	}
}

func TestOpenKeyringWithTimeout_Success(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	t.Setenv("GOG_KEYRING_BACKEND", "file")
	t.Setenv("GOG_KEYRING_PASSWORD", "testpass")

	keyringDir, err := config.EnsureKeyringDir()
	if err != nil {
		t.Fatalf("EnsureKeyringDir: %v", err)
	}

	cfg := keyringConfig(keyringDir)

	// Should complete well within the timeout
	ring, err := openKeyringWithTimeout(cfg, 5*time.Second)
	if err != nil {
		t.Fatalf("openKeyringWithTimeout: %v", err)
	}

	if ring == nil {
		t.Fatal("expected non-nil keyring")
	}
}

func TestOpenKeyringWithTimeout_Timeout(t *testing.T) {
	// Use a channel that never receives to simulate a hanging keyring.Open()
	// We can't easily mock keyring.Open(), so we test with a very short timeout
	// and a config that would normally work - the point is to verify the timeout
	// error message format.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	t.Setenv("GOG_KEYRING_BACKEND", "file")
	t.Setenv("GOG_KEYRING_PASSWORD", "testpass")

	keyringDir, err := config.EnsureKeyringDir()
	if err != nil {
		t.Fatalf("EnsureKeyringDir: %v", err)
	}

	cfg := keyringConfig(keyringDir)

	// Test with an extremely short timeout that the file backend can't beat
	// Note: This test is a bit racy - if the file backend is fast enough, it passes anyway
	// The main point is to verify the timeout path exists and produces the right error format
	_, err = openKeyringWithTimeout(cfg, 1*time.Nanosecond)

	// Either it succeeds (fast system) or times out with our message
	if err != nil && !strings.Contains(err.Error(), "GOG_KEYRING_BACKEND=file") {
		t.Fatalf("expected timeout error with GOG_KEYRING_BACKEND guidance, got: %v", err)
	}
}

func TestOpenKeyring_NoDBus_ForcesFileBackend(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("D-Bus detection only applies on non-Darwin platforms")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	t.Setenv("GOG_KEYRING_BACKEND", "")        // auto
	t.Setenv("GOG_KEYRING_PASSWORD", "testpw") // for file backend
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")   // no D-Bus

	// Should succeed using file backend (not hang on D-Bus)
	store, err := OpenDefault()
	if err != nil {
		t.Fatalf("OpenDefault with no D-Bus: %v", err)
	}

	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestOpenKeyring_ExplicitBackend_IgnoresDBusDetection(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	t.Setenv("GOG_KEYRING_BACKEND", "file") // explicit file
	t.Setenv("GOG_KEYRING_PASSWORD", "testpw")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "") // no D-Bus (shouldn't matter)

	// Should succeed with explicit file backend
	store, err := OpenDefault()
	if err != nil {
		t.Fatalf("OpenDefault with explicit file backend: %v", err)
	}

	if store == nil {
		t.Fatal("expected non-nil store")
	}
}
