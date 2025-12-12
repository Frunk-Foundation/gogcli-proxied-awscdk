package cmd

import "testing"

func TestDriveType(t *testing.T) {
	if got := driveType("application/vnd.google-apps.folder"); got != "folder" {
		t.Fatalf("unexpected: %q", got)
	}
	if got := driveType("application/pdf"); got != "file" {
		t.Fatalf("unexpected: %q", got)
	}
}

func TestFormatDateTime(t *testing.T) {
	if got := formatDateTime(""); got != "-" {
		t.Fatalf("unexpected: %q", got)
	}
	if got := formatDateTime("2025-12-12T14:37:47Z"); got != "2025-12-12 14:37" {
		t.Fatalf("unexpected: %q", got)
	}
	if got := formatDateTime("short"); got != "short" {
		t.Fatalf("unexpected: %q", got)
	}
}

func TestGuessMimeType(t *testing.T) {
	if got := guessMimeType("a.PDF"); got != "application/pdf" {
		t.Fatalf("unexpected: %q", got)
	}
	if got := guessMimeType("a.unknown"); got != "application/octet-stream" {
		t.Fatalf("unexpected: %q", got)
	}
}
