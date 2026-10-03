package kubeproxy

import (
	"net/http"
	"strings"
)

// The hub is the sole Impersonate-* authority (plan §7.2): clients never
// set these headers; kubeproxy strips anything inbound and mints its own
// from the validated JWT identity plus tenant-scoped Keycloak groups.
const (
	headerImpersonateUser  = "Impersonate-User"
	headerImpersonateGroup = "Impersonate-Group"
	headerImpersonateUID   = "Impersonate-Uid"
)

// impersonatePrefix matches Impersonate-User, Impersonate-Group,
// Impersonate-Uid and Impersonate-Extra-* (canonical MIME header form).
const impersonatePrefix = "Impersonate-"

// StripImpersonateHeaders removes every client-supplied Impersonate-*
// header from h in place.
func StripImpersonateHeaders(h http.Header) {
	for k := range h {
		if strings.HasPrefix(k, impersonatePrefix) {
			delete(h, k)
		}
	}
}

// TenantGroups filters Keycloak full-path group claims down to the groups
// of one tenant (/tenant-<slug>/...). Only these may be impersonated.
func TenantGroups(groups []string, slug string) []string {
	prefix := "/tenant-" + slug + "/"
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		if strings.HasPrefix(g, prefix) {
			out = append(out, g)
		}
	}
	return out
}

// MintImpersonateHeaders sets Impersonate-User and Impersonate-Group on h
// from the validated identity. Call StripImpersonateHeaders first. The
// tunnel-agent SA holds impersonate on users/groups/uids only; the
// materialized tenant RBAC binds the impersonated groups.
func MintImpersonateHeaders(h http.Header, user string, groups []string, slug string) {
	h.Set(headerImpersonateUser, user)
	for _, g := range TenantGroups(groups, slug) {
		h.Add(headerImpersonateGroup, g)
	}
}
