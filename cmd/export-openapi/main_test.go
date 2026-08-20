package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestExportContainsFullRESTSurface asserts the offline-exported spec covers
// every key module path so inari-api consumers (CLI, TS clients) never see a
// partial contract.
func TestExportContainsFullRESTSurface(t *testing.T) {
	var buf bytes.Buffer
	if err := run(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("exported spec is empty")
	}
	spec := buf.String()
	paths := []string{
		"/api/v1/tenants",
		"/api/v1/tenants/{org}/clusters",
		"/api/v1/tenants/{org}/catalog",
		"/api/v1/tenants/{org}/instances",
		"/api/v1/tenants/{org}/deploys",
		"/api/v1/tenants/{org}/clusters/{id}/capabilities",
		"/api/v1/tenants/{org}/clusters/{id}/install-manifest",
		"/api/v1/tenants/{org}/approvals",
		"/api/v1/tenants/{org}/cloud-accounts",
		"/api/v1/tenants/{org}/notification-endpoints",
		"/api/v1/tenants/{org}/policies",
		"/api/v1/tenants/{org}/zones",
		"/api/v1/admin/catalog/sync",
	}
	for _, p := range paths {
		if !strings.Contains(spec, p+":") {
			t.Errorf("spec missing path %s", p)
		}
	}
}
