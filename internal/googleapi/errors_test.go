package googleapi

import (
	"errors"
	"testing"

	"github.com/99designs/keyring"
)

func TestAuthRequiredError(t *testing.T) {
	cause := keyring.ErrKeyNotFound
	err := &AuthRequiredError{Service: "gmail", Email: "a@b.com", Cause: cause}
	if err.Error() == "" {
		t.Fatalf("expected message")
	}
	if !errors.Is(err, cause) {
		t.Fatalf("expected unwrap")
	}
}
