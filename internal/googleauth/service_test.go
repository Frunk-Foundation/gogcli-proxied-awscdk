package googleauth

import "testing"

func TestParseService(t *testing.T) {
	tests := []struct {
		in   string
		want Service
	}{
		{"gmail", ServiceGmail},
		{"GMAIL", ServiceGmail},
		{"calendar", ServiceCalendar},
		{"drive", ServiceDrive},
		{"docs", ServiceDocs},
		{"contacts", ServiceContacts},
		{"tasks", ServiceTasks},
		{"people", ServicePeople},
		{"sheets", ServiceSheets},
		{"keep", ServiceKeep},
	}
	for _, tt := range tests {
		got, err := ParseService(tt.in)
		if err != nil {
			t.Fatalf("ParseService(%q) err: %v", tt.in, err)
		}

		if got != tt.want {
			t.Fatalf("ParseService(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseService_Invalid(t *testing.T) {
	if _, err := ParseService("nope"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestExtractCodeAndState(t *testing.T) {
	code, state, err := extractCodeAndState("http://localhost:1/?code=abc&state=xyz")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if code != "abc" || state != "xyz" {
		t.Fatalf("unexpected: code=%q state=%q", code, state)
	}
}

func TestExtractCodeAndState_Errors(t *testing.T) {
	if _, _, err := extractCodeAndState("not a url"); err == nil {
		t.Fatalf("expected error")
	}

	if _, _, err := extractCodeAndState("http://localhost:1/?state=xyz"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestAllServices(t *testing.T) {
	svcs := AllServices()
	if len(svcs) != 9 {
		t.Fatalf("unexpected: %v", svcs)
	}
	seen := make(map[Service]bool)

	for _, s := range svcs {
		seen[s] = true
	}

	for _, want := range []Service{ServiceGmail, ServiceCalendar, ServiceDrive, ServiceDocs, ServiceContacts, ServiceTasks, ServicePeople, ServiceSheets, ServiceKeep} {
		if !seen[want] {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestUserServices(t *testing.T) {
	svcs := UserServices()
	if len(svcs) != 8 {
		t.Fatalf("unexpected: %v", svcs)
	}

	seenDocs := false
	for _, s := range svcs {
		switch s {
		case ServiceDocs:
			seenDocs = true
		case ServiceKeep:
			t.Fatalf("unexpected keep in user services")
		}
	}

	if !seenDocs {
		t.Fatalf("missing docs in user services")
	}
}

func TestUserServiceCSV(t *testing.T) {
	want := "gmail,calendar,drive,docs,contacts,tasks,sheets,people"
	if got := UserServiceCSV(); got != want {
		t.Fatalf("unexpected user services csv: %q", got)
	}
}

func TestServiceOrderCoverage(t *testing.T) {
	seen := make(map[Service]bool)
	for _, svc := range serviceOrder {
		seen[svc] = true

		if _, ok := serviceInfoByService[svc]; !ok {
			t.Fatalf("missing info for %q", svc)
		}
	}

	for svc := range serviceInfoByService {
		if !seen[svc] {
			t.Fatalf("service %q missing from order", svc)
		}
	}
}

func TestScopesForServices_UnionSorted(t *testing.T) {
	scopes, err := ScopesForServices([]Service{ServiceContacts, ServiceGmail, ServiceTasks, ServicePeople, ServiceContacts})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if len(scopes) < 3 {
		t.Fatalf("unexpected scopes: %v", scopes)
	}
	// Ensure stable sorting.
	for i := 1; i < len(scopes); i++ {
		if scopes[i-1] > scopes[i] {
			t.Fatalf("not sorted: %v", scopes)
		}
	}
	// Ensure expected scopes are included.
	want := []string{
		"https://mail.google.com/",
		"https://www.googleapis.com/auth/contacts",
		"https://www.googleapis.com/auth/contacts.other.readonly",
		"https://www.googleapis.com/auth/directory.readonly",
		"https://www.googleapis.com/auth/tasks",
		"profile",
	}
	for _, w := range want {
		found := false
		for _, s := range scopes {
			if s == w {
				found = true
				break
			}
		}

		if !found {
			t.Fatalf("missing scope %q in %v", w, scopes)
		}
	}
}

func TestScopes_DocsIncludesDriveScope(t *testing.T) {
	scopes, err := Scopes(ServiceDocs)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	want := "https://www.googleapis.com/auth/drive"
	for _, scope := range scopes {
		if scope == want {
			return
		}
	}

	t.Fatalf("missing %q in %v", want, scopes)
}

func TestScopes_UnknownService(t *testing.T) {
	if _, err := Scopes(Service("nope")); err == nil {
		t.Fatalf("expected error")
	}
}
