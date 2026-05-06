package admin

import (
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"google.golang.org/genproto/googleapis/api/annotations"
)

func TestHTTPRulePathTemplates(t *testing.T) {
	rule := &annotations.HttpRule{
		Pattern: &annotations.HttpRule_Get{Get: "/api/resources/{id}"},
		AdditionalBindings: []*annotations.HttpRule{
			{Pattern: &annotations.HttpRule_Delete{Delete: "/api/resources/by-name/{name=projects/*}"}},
			{Pattern: &annotations.HttpRule_Custom{Custom: &annotations.CustomHttpPattern{Kind: "HEAD", Path: "/api/resources/{resource.id}"}}},
		},
	}

	got := httpRulePathTemplates(rule)
	want := []string{
		"/api/resources/{id}",
		"/api/resources/by-name/{name=projects/*}",
		"/api/resources/{resource.id}",
	}

	if len(got) != len(want) {
		t.Fatalf("unexpected path template length: got=%d want=%d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected template at index %d: got=%q want=%q", i, got[i], want[i])
		}
	}
}

func TestExtractHTTPPathVariables(t *testing.T) {
	got := extractHTTPPathVariables("/api/resources/{id}/children/{name=projects/*}/detail/{resource.id}")
	want := []pathVariable{
		{resourceType: "id", pattern: "*"},
		{resourceType: "name", pattern: "projects/*"},
		{resourceType: "resource.id", pattern: "*"},
	}

	if len(got) != len(want) {
		t.Fatalf("unexpected variable length: got=%d want=%d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected variable at index %d: got=%+v want=%+v", i, got[i], want[i])
		}
	}
}

func TestAppendPathVariableSelectors(t *testing.T) {
	in := []*adminv1.Action_ResourceSelector{
		{ResourceType: "id", Pattern: "*"},
	}
	templates := []string{
		"/api/resources/{id}",
		"/api/resources/{name=projects/*}",
		"/api/resources/{id}",
		"/api/resources/{resource.id}",
	}

	got := appendPathVariableSelectors("test-service", in, templates)
	want := []adminv1.Action_ResourceSelector{
		{ResourceType: "id", Pattern: "*"},
		{ResourceType: "name", Pattern: "grn:test-service:${region_code}:${account_id}:name/projects/*"},
		{ResourceType: "resource.id", Pattern: "grn:test-service:${region_code}:${account_id}:resource.id/*"},
	}

	if len(got) != len(want) {
		t.Fatalf("unexpected selectors length: got=%d want=%d", len(got), len(want))
	}
	for i := range want {
		if got[i] == nil {
			t.Fatalf("selector at index %d is nil", i)
		}
		if got[i].GetResourceType() != want[i].ResourceType || got[i].GetPattern() != want[i].Pattern {
			t.Fatalf("unexpected selector at index %d: got=(%s,%s) want=(%s,%s)", i, got[i].GetResourceType(), got[i].GetPattern(), want[i].ResourceType, want[i].Pattern)
		}
	}
}
