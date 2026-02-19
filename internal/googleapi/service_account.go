package googleapi

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var newServiceAccountTokenSource = func(ctx context.Context, keyJSON []byte, subject string, scopes []string) (oauth2.TokenSource, error) {
	cfg, err := google.JWTConfigFromJSON(keyJSON, scopes...)
	if err != nil {
		return nil, fmt.Errorf("parse service account: %w", err)
	}
	cfg.Subject = subject

	// Ensure token exchanges don't hang forever.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Timeout: defaultHTTPTimeout})

	return cfg.TokenSource(ctx), nil
}
