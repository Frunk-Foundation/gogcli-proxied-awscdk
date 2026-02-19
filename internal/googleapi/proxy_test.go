//nolint:wsl_v5 // tests prioritize compact scenario setup over whitespace-style rules.
package googleapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/steipete/gogcli/internal/config"
)

type captureRT struct {
	last *http.Request
}

func (c *captureRT) RoundTrip(r *http.Request) (*http.Response, error) {
	c.last = r
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       http.NoBody,
		Header:     make(http.Header),
		Request:    r,
	}, nil
}

type stubCredsProvider struct {
	creds aws.Credentials
	err   error
}

func (s *stubCredsProvider) Retrieve(context.Context) (aws.Credentials, error) {
	if s.err != nil {
		return aws.Credentials{}, s.err
	}
	return s.creds, nil
}

type stubSigner struct {
	err error
}

func (s *stubSigner) SignHTTP(_ context.Context, credentials aws.Credentials, r *http.Request, payloadHash string, service string, region string, signingTime time.Time, _ ...func(*signerOptions)) error {
	if s.err != nil {
		return s.err
	}
	r.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/scope, SignedHeaders=host;x-amz-date, Signature=fake", credentials.AccessKeyID))
	r.Header.Set("X-Amz-Date", signingTime.UTC().Format("20060102T150405Z"))
	if credentials.SessionToken != "" {
		r.Header.Set("X-Amz-Security-Token", credentials.SessionToken)
	}
	r.Header.Set("X-Signed-Payload", payloadHash)
	r.Header.Set("X-Signed-Service", service)
	r.Header.Set("X-Signed-Region", region)
	return nil
}

func TestLoadProxyConfig_MissingEnv(t *testing.T) {
	t.Setenv(envProxyBaseURL, "")
	t.Setenv(envProxyAPIKey, "")

	_, err := loadProxyConfig()
	if err == nil {
		t.Fatalf("expected error")
	}
	var pce *ProxyConfigError
	if !errors.As(err, &pce) || pce == nil {
		t.Fatalf("expected ProxyConfigError, got: %T %v", err, err)
	}
	if !strings.Contains(err.Error(), errProxyConfig.Error()) || !strings.Contains(err.Error(), envProxyBaseURL) || !strings.Contains(err.Error(), envProxyAPIKey) {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pce.Missing) != 2 {
		t.Fatalf("unexpected missing: %#v", pce.Missing)
	}
}

func TestLoadProxyConfig_UsesConfigFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	t.Setenv(envProxyBaseURL, "")
	t.Setenv(envProxyAPIKey, "")
	if err := config.WriteConfig(config.File{
		ProxyBaseURL: "https://abc123.execute-api.us-east-1.amazonaws.com/prod",
		ProxyAPIKey:  "cfg-key",
	}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	got, err := loadProxyConfig()
	if err != nil {
		t.Fatalf("loadProxyConfig: %v", err)
	}
	if got.APIKey != "cfg-key" {
		t.Fatalf("api key = %q", got.APIKey)
	}
	if got.Region != "us-east-1" {
		t.Fatalf("region = %q", got.Region)
	}
	if got.Endpoint != "https://abc123.execute-api.us-east-1.amazonaws.com/prod/" {
		t.Fatalf("endpoint = %q", got.Endpoint)
	}
}

func TestInferRegionFromExecuteAPIHost(t *testing.T) {
	if got := inferRegionFromExecuteAPIHost("abc123.execute-api.us-east-1.amazonaws.com"); got != "us-east-1" {
		t.Fatalf("unexpected region: %q", got)
	}
	if got := inferRegionFromExecuteAPIHost("api.example.com"); got != "" {
		t.Fatalf("expected empty region, got %q", got)
	}
}

func TestProxyTransport_InjectsHeadersAndSigns(t *testing.T) {
	base := &captureRT{}
	tr := &apiGatewayProxyTransport{
		Base:                base,
		Region:              "us-east-1",
		APIKey:              "k",
		Account:             "User@Example.com",
		CredentialsProvider: &stubCredsProvider{creds: aws.Credentials{AccessKeyID: "AKID", SecretAccessKey: "SECRET", SessionToken: "TOKEN"}},
		Signer:              &stubSigner{},
		Now: func() time.Time {
			return time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC)
		},
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://abc123.execute-api.us-east-1.amazonaws.com/prod/gmail/v1/users/me/labels?x=1", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	_ = resp.Body.Close()

	if base.last == nil {
		t.Fatalf("expected captured request")
	}
	r := base.last
	if got := r.Header.Get("x-api-key"); got != "k" {
		t.Fatalf("x-api-key=%q", got)
	}
	if got := r.Header.Get("X-GOG-Account"); got != "user@example.com" {
		t.Fatalf("X-GOG-Account=%q", got)
	}
	if got := r.Header.Get("X-Amz-Date"); got == "" {
		t.Fatalf("expected X-Amz-Date")
	}
	if got := r.Header.Get("X-Amz-Security-Token"); got != "TOKEN" {
		t.Fatalf("X-Amz-Security-Token=%q", got)
	}
	authz := r.Header.Get("Authorization")
	if authz == "" || !strings.Contains(authz, "AWS4-HMAC-SHA256") {
		t.Fatalf("unexpected Authorization=%q", authz)
	}
	if got := r.Header.Get("X-Signed-Region"); got != "us-east-1" {
		t.Fatalf("X-Signed-Region=%q", got)
	}
}

func TestProxyTransport_CredentialProviderError(t *testing.T) {
	base := &captureRT{}
	tr := &apiGatewayProxyTransport{
		Base:                base,
		Region:              "us-east-1",
		APIKey:              "k",
		Account:             "user@example.com",
		CredentialsProvider: &stubCredsProvider{err: errors.New("no creds")},
		Signer:              &stubSigner{},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://abc123.execute-api.us-east-1.amazonaws.com/prod/gmail/v1/users/me/labels", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	_, err = tr.RoundTrip(req)
	if err == nil || !strings.Contains(err.Error(), "no creds") {
		t.Fatalf("expected provider error, got %v", err)
	}
}

func TestProxyTransport_SignerError(t *testing.T) {
	base := &captureRT{}
	tr := &apiGatewayProxyTransport{
		Base:                base,
		Region:              "us-east-1",
		APIKey:              "k",
		Account:             "user@example.com",
		CredentialsProvider: &stubCredsProvider{creds: aws.Credentials{AccessKeyID: "AKID", SecretAccessKey: "SECRET"}},
		Signer:              &stubSigner{err: errors.New("sign failed")},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://abc123.execute-api.us-east-1.amazonaws.com/prod/gmail/v1/users/me/labels", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	_, err = tr.RoundTrip(req)
	if err == nil || !strings.Contains(err.Error(), "sign failed") {
		t.Fatalf("expected signer error, got %v", err)
	}
}
