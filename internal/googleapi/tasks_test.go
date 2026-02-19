package googleapi

import (
	"context"
	"testing"

	"github.com/steipete/gogcli/internal/config"
	"github.com/steipete/gogcli/internal/secrets"
)

func TestNewTasks(t *testing.T) {
	t.Setenv("GOG_PROXY_BASE_URL", "https://abc123.execute-api.us-east-1.amazonaws.com/prod")
	t.Setenv("GOG_PROXY_API_KEY", "k")

	origRead := readClientCredentials
	origOpen := openSecretsStore

	t.Cleanup(func() {
		readClientCredentials = origRead
		openSecretsStore = origOpen
	})

	readClientCredentials = func(string) (config.ClientCredentials, error) {
		t.Fatalf("readClientCredentials should not be called")
		return config.ClientCredentials{}, nil
	}
	openSecretsStore = func() (secrets.Store, error) {
		t.Fatalf("openSecretsStore should not be called")
		panic("unreachable")
	}

	svc, err := NewTasks(context.Background(), "a@b.com")
	if err != nil {
		t.Fatalf("NewTasks: %v", err)
	}

	if svc == nil {
		t.Fatalf("expected service")
	}
}
