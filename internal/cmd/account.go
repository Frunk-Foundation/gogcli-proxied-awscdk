package cmd

import (
	"os"
	"strings"

	"github.com/steipete/gogcli/internal/config"
)

func requireAccount(flags *RootFlags) (string, error) {
	if flags != nil {
		if v := strings.TrimSpace(flags.Account); v != "" {
			if resolved, ok, err := resolveAccountAlias(v); err != nil {
				return "", err
			} else if ok {
				return resolved, nil
			}
			if shouldAutoSelectAccount(v) {
				v = ""
			}
			if v != "" {
				return v, nil
			}
		}
	}
	cfg, err := config.ReadConfig()
	if err != nil {
		return "", err
	}
	if v := strings.TrimSpace(cfg.DefaultAccount); v != "" {
		if resolved, ok, err := resolveAccountAlias(v); err != nil {
			return "", err
		} else if ok {
			return resolved, nil
		}
		if shouldAutoSelectAccount(v) {
			v = ""
		}
		if v != "" {
			return v, nil
		}
	}
	if v := strings.TrimSpace(os.Getenv("GOG_ACCOUNT")); v != "" {
		if resolved, ok, err := resolveAccountAlias(v); err != nil {
			return "", err
		} else if ok {
			return resolved, nil
		}
		if shouldAutoSelectAccount(v) {
			v = ""
		}
		if v != "" {
			return v, nil
		}
	}
	return "", usage("missing --account (or set default_account in config.json or GOG_ACCOUNT)")
}

func resolveAccountAlias(value string) (string, bool, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "@") || shouldAutoSelectAccount(value) {
		return "", false, nil
	}
	return config.ResolveAccountAlias(value)
}

func shouldAutoSelectAccount(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "auto", "default":
		return true
	default:
		return false
	}
}
