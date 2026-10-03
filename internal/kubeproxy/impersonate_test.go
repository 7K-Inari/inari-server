package kubeproxy

import (
	"net/http"
	"testing"
)

func TestStripImpersonateHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Impersonate-User", "mallory")
	h.Add("Impersonate-Group", "system:masters")
	h.Set("Impersonate-Uid", "1234")
	h.Set("Impersonate-Extra-Scope", "x")
	h.Set("Authorization", "Bearer tok")
	h.Set("Accept", "application/json")
	StripImpersonateHeaders(h)
	for k := range h {
		if k == "Impersonate-User" || k == "Impersonate-Group" || k == "Impersonate-Uid" || k == "Impersonate-Extra-Scope" {
			t.Fatalf("header %s survived stripping", k)
		}
	}
	if h.Get("Authorization") == "" || h.Get("Accept") == "" {
		t.Fatal("unrelated headers were stripped")
	}
}

func TestTenantGroups(t *testing.T) {
	groups := []string{"/tenant-acme/devs", "/tenant-acme", "/tenant-other/admins", "/platform-admins", "tenant-acme/noslash"}
	got := TenantGroups(groups, "acme")
	if len(got) != 1 || got[0] != "/tenant-acme/devs" {
		t.Fatalf("TenantGroups = %v, want [/tenant-acme/devs]", got)
	}
}

func TestMintImpersonateHeaders(t *testing.T) {
	h := http.Header{}
	MintImpersonateHeaders(h, "user-123", []string{"/tenant-acme/devs", "/tenant-other/x"}, "acme")
	if got := h.Get(headerImpersonateUser); got != "user-123" {
		t.Fatalf("Impersonate-User = %q", got)
	}
	groups := h.Values(headerImpersonateGroup)
	if len(groups) != 1 || groups[0] != "/tenant-acme/devs" {
		t.Fatalf("Impersonate-Group = %v", groups)
	}
	if h.Get(headerImpersonateUID) != "" {
		t.Fatal("UID must never be minted by the hub")
	}
}

func TestStripThenMint(t *testing.T) {
	h := http.Header{}
	h.Set("Impersonate-User", "mallory")
	StripImpersonateHeaders(h)
	MintImpersonateHeaders(h, "user-123", nil, "acme")
	if got := h.Values(headerImpersonateUser); len(got) != 1 || got[0] != "user-123" {
		t.Fatalf("Impersonate-User = %v", got)
	}
}
