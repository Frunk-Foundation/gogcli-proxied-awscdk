package cmd

import (
	"path/filepath"
	"testing"

	"github.com/steipete/gogcli/internal/config"
)

func TestRequireAccount_PrefersFlag(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "env@example.com")
	flags := &RootFlags{Account: "flag@example.com"}
	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "flag@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_UsesEnv(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "env@example.com")
	flags := &RootFlags{}
	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "env@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_UsesConfigDefaultAccount(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	t.Setenv("GOG_ACCOUNT", "")
	if err := config.WriteConfig(config.File{
		DefaultAccount: "config@example.com",
	}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	got, err := requireAccount(&RootFlags{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "config@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_ConfigBeforeEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	t.Setenv("GOG_ACCOUNT", "env@example.com")
	if err := config.WriteConfig(config.File{
		DefaultAccount: "config@example.com",
	}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	got, err := requireAccount(&RootFlags{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "config@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_ResolvesAliasFlag(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	if err := config.WriteConfig(config.File{
		AccountAliases: map[string]string{"work": "alias@example.com"},
	}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	flags := &RootFlags{Account: "work"}
	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "alias@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_ResolvesAliasEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	if err := config.WriteConfig(config.File{
		AccountAliases: map[string]string{"work": "alias@example.com"},
	}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("GOG_ACCOUNT", "work")
	flags := &RootFlags{}
	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "alias@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_Missing(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "")
	flags := &RootFlags{}
	_, err := requireAccount(flags)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestRequireAccount_AutoAndDefaultRejected(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "")
	for _, v := range []string{"auto", "default", "AUTO", " Default "} {
		flags := &RootFlags{Account: v}
		if _, err := requireAccount(flags); err == nil {
			t.Fatalf("expected error for %q", v)
		}
	}
}
