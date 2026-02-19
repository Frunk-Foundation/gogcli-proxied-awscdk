package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))

	path, err := ConfigPath()
	if err != nil {
		t.Fatalf("ConfigPath: %v", err)
	}

	if filepath.Base(path) != "config.json" {
		t.Fatalf("unexpected config file: %q", filepath.Base(path))
	}

	if filepath.Base(filepath.Dir(path)) != AppName {
		t.Fatalf("unexpected config dir: %q", filepath.Dir(path))
	}
}

func TestReadConfig_Missing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))

	cfg, err := ReadConfig()
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}

	if cfg.KeyringBackend != "" {
		t.Fatalf("expected empty config, got %q", cfg.KeyringBackend)
	}
}

func TestReadConfig_JSON5(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))

	path, err := ConfigPath()
	if err != nil {
		t.Fatalf("ConfigPath: %v", err)
	}

	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	data := `{
  // allow comments + trailing commas
  keyring_backend: "file",
}`

	if err = os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := ReadConfig()
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}

	if got := strings.TrimSpace(cfg.KeyringBackend); got != "file" {
		t.Fatalf("expected keyring_backend=file, got %q", got)
	}
}

func TestReadConfig_ProxyFields(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))

	path, err := ConfigPath()
	if err != nil {
		t.Fatalf("ConfigPath: %v", err)
	}

	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	data := `{
	  proxy_base_url: "https://abc123.execute-api.us-east-1.amazonaws.com/prod",
	  proxy_api_key: "key-from-config",
	  default_account: "user@example.com"
	}`

	if err = os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := ReadConfig()
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	if cfg.ProxyBaseURL == "" || cfg.ProxyAPIKey == "" || cfg.DefaultAccount == "" {
		t.Fatalf("missing proxy fields: %#v", cfg)
	}
}
