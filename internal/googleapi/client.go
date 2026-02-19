package googleapi

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/99designs/keyring"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"

	"github.com/steipete/gogcli/internal/authclient"
	"github.com/steipete/gogcli/internal/config"
	"github.com/steipete/gogcli/internal/googleauth"
	"github.com/steipete/gogcli/internal/secrets"
)

const defaultHTTPTimeout = 30 * time.Second

var (
	readClientCredentials = config.ReadClientCredentialsFor
	openSecretsStore      = secrets.OpenDefault
)

func tokenSourceForAccount(ctx context.Context, service googleauth.Service, email string) (oauth2.TokenSource, error) {
	client, err := authclient.ResolveClient(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("resolve client: %w", err)
	}

	creds, err := readClientCredentials(client)
	if err != nil {
		return nil, fmt.Errorf("read credentials: %w", err)
	}

	var requiredScopes []string

	if scopes, err := googleauth.Scopes(service); err != nil {
		return nil, fmt.Errorf("resolve scopes: %w", err)
	} else {
		requiredScopes = scopes
	}

	return tokenSourceForAccountScopes(ctx, string(service), email, client, creds.ClientID, creds.ClientSecret, requiredScopes)
}

func tokenSourceForAccountScopes(ctx context.Context, serviceLabel string, email string, client string, clientID string, clientSecret string, requiredScopes []string) (oauth2.TokenSource, error) {
	var store secrets.Store

	if s, err := openSecretsStore(); err != nil {
		return nil, fmt.Errorf("open secrets store: %w", err)
	} else {
		store = s
	}

	var tok secrets.Token

	if t, err := store.GetToken(client, email); err != nil {
		if errors.Is(err, keyring.ErrKeyNotFound) {
			return nil, &AuthRequiredError{Service: serviceLabel, Email: email, Client: client, Cause: err}
		}

		return nil, fmt.Errorf("get token for %s: %w", email, err)
	} else {
		tok = t
	}

	cfg := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     google.Endpoint,
		Scopes:       requiredScopes,
	}

	// Ensure refresh-token exchanges don't hang forever.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Timeout: defaultHTTPTimeout})

	return cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: tok.RefreshToken}), nil
}

func optionsForAccount(ctx context.Context, service googleauth.Service, email string) ([]option.ClientOption, error) {
	scopes, err := googleauth.Scopes(service)
	if err != nil {
		return nil, fmt.Errorf("resolve scopes: %w", err)
	}

	return optionsForAccountScopes(ctx, string(service), email, scopes)
}

func optionsForAccountScopes(ctx context.Context, serviceLabel string, email string, scopes []string) ([]option.ClientOption, error) {
	slog.Debug("creating client options with custom scopes", "serviceLabel", serviceLabel, "email", email, "scopeCount", len(scopes))

	proxyCfg, err := loadProxyConfig()
	if err != nil {
		return nil, err
	}
	credsProvider, err := loadAWSCredentialsProvider(ctx, proxyCfg.Region)
	if err != nil {
		return nil, err
	}

	baseTransport := newBaseTransport()
	// Inject proxy auth + SigV4, then wrap with retry logic for 429 and 5xx errors.
	retryTransport := NewRetryTransport(&apiGatewayProxyTransport{
		Base:                baseTransport,
		Region:              proxyCfg.Region,
		APIKey:              proxyCfg.APIKey,
		Account:             email,
		CredentialsProvider: credsProvider,
	})
	c := &http.Client{
		Transport: retryTransport,
		Timeout:   defaultHTTPTimeout,
	}

	slog.Debug("client options with custom scopes created successfully", "serviceLabel", serviceLabel, "email", email)

	return []option.ClientOption{
		option.WithHTTPClient(c),
		option.WithEndpoint(proxyCfg.Endpoint),
	}, nil
}

func newBaseTransport() *http.Transport {
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok || defaultTransport == nil {
		return &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			DisableCompression: true,
		}
	}

	// Clone() deep-copies TLSClientConfig, so no additional clone needed.
	transport := defaultTransport.Clone()

	transport.DisableCompression = true
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		return transport
	}

	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	}

	return transport
}
