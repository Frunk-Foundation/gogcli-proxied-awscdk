package googleauth

import (
	"bytes"
	"html/template"
	"testing"
)

func TestEmbeddedTemplates_Parse(t *testing.T) {
	cases := []struct {
		name string
		src  string
		data any
	}{
		{name: "accounts", src: accountsTemplate, data: struct{ CSRFToken string }{CSRFToken: "csrf"}},
		{name: "success_with_email", src: successTemplate, data: struct {
			Email    string
			Services []string
		}{Email: "a@b.com", Services: []string{"gmail", "drive"}}},
		{name: "success_without_email", src: successTemplate, data: struct {
			Email    string
			Services []string
		}{}},
		{name: "error", src: errorTemplate, data: struct{ Error string }{Error: "boom"}},
		{name: "cancelled", src: cancelledTemplate, data: struct{}{}},
	}
	for _, tc := range cases {
		if tc.src == "" {
			t.Fatalf("%s template is empty", tc.name)
		}
		tmpl, err := template.New(tc.name).Parse(tc.src)
		if err != nil {
			t.Fatalf("%s parse: %v", tc.name, err)
		}
		var buf bytes.Buffer
		if execErr := tmpl.Execute(&buf, tc.data); execErr != nil {
			t.Fatalf("%s execute: %v", tc.name, execErr)
		}
		if buf.Len() == 0 {
			t.Fatalf("%s execute: empty output", tc.name)
		}
	}
}
