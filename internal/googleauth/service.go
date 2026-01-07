package googleauth

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

type Service string

const (
	ServiceGmail    Service = "gmail"
	ServiceCalendar Service = "calendar"
	ServiceDrive    Service = "drive"
	ServiceDocs     Service = "docs"
	ServiceContacts Service = "contacts"
	ServiceTasks    Service = "tasks"
	ServicePeople   Service = "people"
	ServiceSheets   Service = "sheets"
	ServiceKeep     Service = "keep"
)

var errUnknownService = errors.New("unknown service")

type serviceInfo struct {
	scopes []string
	user   bool
}

var serviceOrder = []Service{
	ServiceGmail,
	ServiceCalendar,
	ServiceDrive,
	ServiceDocs,
	ServiceContacts,
	ServiceTasks,
	ServiceSheets,
	ServicePeople,
	ServiceKeep,
}

var serviceInfoByService = map[Service]serviceInfo{
	ServiceGmail: {
		scopes: []string{"https://mail.google.com/"},
		user:   true,
	},
	ServiceCalendar: {
		scopes: []string{"https://www.googleapis.com/auth/calendar"},
		user:   true,
	},
	ServiceDrive: {
		scopes: []string{"https://www.googleapis.com/auth/drive"},
		user:   true,
	},
	ServiceDocs: {
		// Docs commands are implemented via Drive APIs (export/copy/create),
		// so use Drive scope to match actual access needs.
		scopes: []string{"https://www.googleapis.com/auth/drive"},
		user:   true,
	},
	ServiceContacts: {
		scopes: []string{
			"https://www.googleapis.com/auth/contacts",
			"https://www.googleapis.com/auth/contacts.other.readonly",
			"https://www.googleapis.com/auth/directory.readonly",
		},
		user: true,
	},
	ServiceTasks: {
		scopes: []string{"https://www.googleapis.com/auth/tasks"},
		user:   true,
	},
	ServicePeople: {
		// Needed for "people/me" requests.
		scopes: []string{"profile"},
		user:   true,
	},
	ServiceSheets: {
		scopes: []string{"https://www.googleapis.com/auth/spreadsheets"},
		user:   true,
	},
	ServiceKeep: {
		scopes: []string{"https://www.googleapis.com/auth/keep"},
		user:   false,
	},
}

func ParseService(s string) (Service, error) {
	parsed := Service(strings.ToLower(strings.TrimSpace(s)))
	if _, ok := serviceInfoByService[parsed]; ok {
		return parsed, nil
	}

	return "", fmt.Errorf("%w %q (expected %s)", errUnknownService, s, serviceNames(AllServices(), "|"))
}

// UserServices are the default OAuth services intended for consumer ("regular") accounts.
func UserServices() []Service {
	return filteredServices(func(info serviceInfo) bool { return info.user })
}

func AllServices() []Service {
	out := make([]Service, len(serviceOrder))
	copy(out, serviceOrder)

	return out
}

func Scopes(service Service) ([]string, error) {
	info, ok := serviceInfoByService[service]
	if !ok {
		return nil, errUnknownService
	}

	return append([]string(nil), info.scopes...), nil
}

func ScopesForServices(services []Service) ([]string, error) {
	set := make(map[string]struct{})

	for _, svc := range services {
		scopes, err := Scopes(svc)
		if err != nil {
			return nil, err
		}

		for _, s := range scopes {
			set[s] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))

	for s := range set {
		out = append(out, s)
	}
	// stable ordering (useful for tests + auth URL diffs)
	sort.Strings(out)

	return out, nil
}

func UserServiceCSV() string {
	return serviceNames(UserServices(), ",")
}

func serviceNames(services []Service, sep string) string {
	names := make([]string, 0, len(services))
	for _, svc := range services {
		names = append(names, string(svc))
	}

	return strings.Join(names, sep)
}

func filteredServices(include func(info serviceInfo) bool) []Service {
	out := make([]Service, 0, len(serviceOrder))
	for _, svc := range serviceOrder {
		info, ok := serviceInfoByService[svc]
		if !ok {
			continue
		}

		if include == nil || include(info) {
			out = append(out, svc)
		}
	}

	return out
}
