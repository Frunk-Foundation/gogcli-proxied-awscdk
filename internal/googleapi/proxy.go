package googleapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/steipete/gogcli/internal/config"
)

const (
	envProxyBaseURL = "GOG_PROXY_BASE_URL"
	envProxyAPIKey  = "GOG_PROXY_API_KEY" //nolint:gosec // env var name, not credential material

	awsServiceExecuteAPI = "execute-api"
)

var errProxyConfig = errors.New("proxy config error")

var (
	errMissingAWSCredentials = errors.New("missing AWS credentials (configure the AWS SDK default credential chain)")
	errNilRequest            = errors.New("nil request")
	errNilBaseTransport      = errors.New("nil base transport")
)

// ProxyConfigError indicates gogcli is missing required proxy configuration.
// This is treated as a config error (stable exit code) by the CLI.
type ProxyConfigError struct {
	Missing []string
	Invalid []string
	Cause   error
}

func (e *ProxyConfigError) Error() string {
	parts := make([]string, 0, 2)
	if len(e.Missing) > 0 {
		parts = append(parts, "missing: "+strings.Join(e.Missing, ", "))
	}
	if len(e.Invalid) > 0 {
		parts = append(parts, "invalid: "+strings.Join(e.Invalid, ", "))
	}
	msg := strings.TrimSpace(strings.Join(parts, "; "))
	if msg == "" {
		msg = "invalid proxy configuration"
	}
	return fmt.Sprintf("%s (%s)", errProxyConfig.Error(), msg)
}

func (e *ProxyConfigError) Unwrap() error {
	if e.Cause != nil {
		return e.Cause
	}
	return errProxyConfig
}

type proxyConfig struct {
	Endpoint string
	APIKey   string
	Region   string
}

func loadProxyConfig() (proxyConfig, error) {
	cfg, err := config.ReadConfig()
	if err != nil {
		return proxyConfig{}, err
	}
	base := strings.TrimSpace(cfg.ProxyBaseURL)
	apiKey := strings.TrimSpace(cfg.ProxyAPIKey)
	if base == "" {
		base = strings.TrimSpace(os.Getenv(envProxyBaseURL))
	}
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv(envProxyAPIKey))
	}

	var missing []string
	if base == "" {
		missing = append(missing, envProxyBaseURL)
	}
	if apiKey == "" {
		missing = append(missing, envProxyAPIKey)
	}
	if len(missing) > 0 {
		return proxyConfig{}, &ProxyConfigError{Missing: missing}
	}

	u, err := url.Parse(base)
	if err != nil {
		return proxyConfig{}, &ProxyConfigError{Invalid: []string{envProxyBaseURL}, Cause: err}
	}
	if u == nil || strings.TrimSpace(u.Scheme) == "" || strings.TrimSpace(u.Host) == "" {
		return proxyConfig{}, &ProxyConfigError{Invalid: []string{envProxyBaseURL}}
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return proxyConfig{}, &ProxyConfigError{Invalid: []string{envProxyBaseURL}}
	}

	// Normalize to a base URL that ends with a slash so google.golang.org/api
	// can safely append service paths like /gmail/v1/... and /drive/v3/....
	if u.Path == "" {
		u.Path = "/"
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	endpoint := u.String()

	region := inferRegionFromExecuteAPIHost(u.Hostname())
	if region == "" {
		region = strings.TrimSpace(os.Getenv("AWS_REGION"))
	}
	if region == "" {
		region = strings.TrimSpace(os.Getenv("AWS_DEFAULT_REGION"))
	}
	if region == "" {
		// For custom domains, users must set AWS_REGION or AWS_DEFAULT_REGION.
		return proxyConfig{}, &ProxyConfigError{Missing: []string{"AWS_REGION (or AWS_DEFAULT_REGION)"}}
	}

	return proxyConfig{
		Endpoint: endpoint,
		APIKey:   apiKey,
		Region:   region,
	}, nil
}

func inferRegionFromExecuteAPIHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	// Typical API Gateway hostname:
	//   {api-id}.execute-api.{region}.amazonaws.com
	parts := strings.Split(host, ".")
	if len(parts) < 5 {
		return ""
	}
	// ... execute-api <region> amazonaws com
	if parts[len(parts)-2] != "amazonaws" || parts[len(parts)-1] != "com" {
		return ""
	}
	if parts[len(parts)-4] != "execute-api" {
		return ""
	}
	region := strings.TrimSpace(parts[len(parts)-3])
	if region == "" {
		return ""
	}
	return region
}

type credentialProvider interface {
	Retrieve(context.Context) (aws.Credentials, error)
}

type signerOptions = v4.SignerOptions

type sigV4HTTPSigner interface {
	SignHTTP(ctx context.Context, credentials aws.Credentials, r *http.Request, payloadHash string, service string, region string, signingTime time.Time, optFns ...func(*signerOptions)) error
}

func loadAWSCredentialsProvider(ctx context.Context, region string) (credentialProvider, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load aws default config: %w", err)
	}
	if cfg.Credentials == nil {
		return nil, errMissingAWSCredentials
	}
	return cfg.Credentials, nil
}

// apiGatewayProxyTransport injects API Gateway auth and account routing headers,
// and signs requests with SigV4 (execute-api).
//
// Note: we intentionally disable HTTP compression in the base transport so the
// net/http transport does not add Accept-Encoding after signing.
type apiGatewayProxyTransport struct {
	Base                http.RoundTripper
	Region              string
	APIKey              string
	Account             string
	CredentialsProvider credentialProvider
	Signer              sigV4HTTPSigner
	Now                 func() time.Time
}

func (t *apiGatewayProxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errNilRequest
	}
	if t.Base == nil {
		return nil, errNilBaseTransport
	}

	now := time.Now
	if t.Now != nil {
		now = t.Now
	}

	// Clone request to avoid mutating the input across retries.
	r := req.Clone(req.Context())
	if req.Body != nil {
		r.Body = req.Body
	}
	r.GetBody = req.GetBody

	// Required routing/auth headers for the proxy.
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	r.Header.Set("x-api-key", t.APIKey)
	r.Header.Set("X-GOG-Account", strings.ToLower(strings.TrimSpace(t.Account)))

	payloadHash, err := payloadSHA256Hex(r)
	if err != nil {
		return nil, err
	}

	provider := t.CredentialsProvider
	if provider == nil {
		provider, err = loadAWSCredentialsProvider(req.Context(), t.Region)
		if err != nil {
			return nil, err
		}
	}
	creds, err := provider.Retrieve(req.Context())
	if err != nil {
		return nil, fmt.Errorf("retrieve aws credentials: %w", err)
	}

	signer := t.Signer
	if signer == nil {
		signer = v4.NewSigner()
	}

	amzTime := now().UTC()
	if err := signer.SignHTTP(req.Context(), creds, r, payloadHash, awsServiceExecuteAPI, t.Region, amzTime); err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}

	resp, err := t.Base.RoundTrip(r)
	if err != nil {
		return nil, fmt.Errorf("proxy roundtrip: %w", err)
	}

	return resp, nil
}

// payloadSHA256Hex returns the SHA256 of the request body without consuming it.
// It uses req.GetBody when available; otherwise it reads req.Body and rewinds it.
func payloadSHA256Hex(req *http.Request) (string, error) {
	if req == nil || req.Body == nil {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:]), nil
	}

	// Fast path: empty body.
	if req.ContentLength == 0 {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:]), nil
	}

	if req.GetBody != nil {
		rc, err := req.GetBody()
		if err != nil {
			return "", fmt.Errorf("get body for signing: %w", err)
		}
		defer rc.Close()
		h := sha256.New()
		if _, err := io.Copy(h, rc); err != nil {
			return "", fmt.Errorf("hash body for signing: %w", err)
		}
		return hex.EncodeToString(h.Sum(nil)), nil
	}

	// Fallback: read and rewind the body.
	b, err := io.ReadAll(req.Body)
	if err != nil {
		return "", fmt.Errorf("read body for signing: %w", err)
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(b))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
