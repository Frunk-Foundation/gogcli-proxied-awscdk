package ui

import (
	"bytes"
	"testing"

	"github.com/muesli/termenv"
)

func TestUIColorFlagValidation(t *testing.T) {
	_, err := New(Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Color: "nope"})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestChooseProfile_NoColorWins(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	got := chooseProfile(termenv.TrueColor, "always")
	if got != termenv.Ascii {
		t.Fatalf("expected ascii")
	}
}

func TestChooseProfile_Always(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	got := chooseProfile(termenv.Ascii, "always")
	if got != termenv.TrueColor {
		t.Fatalf("expected truecolor")
	}
}
