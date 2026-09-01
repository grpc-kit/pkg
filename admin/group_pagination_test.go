package admin

import (
	"context"
	"strings"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"github.com/grpc-kit/pkg/lion/groups"
	"github.com/grpc-kit/pkg/lion/predicate"
	"github.com/grpc-kit/pkg/lion/users"
)

func TestGroupIDPageTokenRoundTrip(t *testing.T) {
	ctx := context.Background()
	token := encodeGroupIDPageToken(42)
	got, err := decodeGroupIDPageToken(ctx, token)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if got != 42 {
		t.Fatalf("decoded ID = %d, want 42", got)
	}
	if got, err := decodeGroupIDPageToken(ctx, ""); err != nil || got != 0 {
		t.Fatalf("empty token = (%d, %v), want (0, nil)", got, err)
	}
}

func TestGroupIDPageTokenRejectsInvalidValues(t *testing.T) {
	ctx := context.Background()
	for _, token := range []string{"not-base64", "MA==", "LTE="} {
		if _, err := decodeGroupIDPageToken(ctx, token); err == nil {
			t.Fatalf("decodeGroupIDPageToken(%q) succeeded, want error", token)
		}
	}
}

func TestRequireIDCursorOrder(t *testing.T) {
	ctx := context.Background()
	if err := requireIDCursorOrder(ctx, "  "); err != nil {
		t.Fatalf("blank order_by: %v", err)
	}
	if err := requireIDCursorOrder(ctx, "created_at desc"); err == nil {
		t.Fatal("custom cursor order succeeded, want error")
	}
}

func renderGroupPredicate(p predicate.Groups) string {
	table := sql.Table(groups.Table).As("groups")
	selector := sql.Select(table.C(groups.FieldID)).From(table)
	selector.SetDialect(dialect.Postgres)
	p(selector)
	query, _ := selector.Query()
	return query
}

func renderUserPredicate(p predicate.Users) string {
	table := sql.Table(users.Table).As("users")
	selector := sql.Select(table.C(users.FieldID)).From(table)
	selector.SetDialect(dialect.Postgres)
	p(selector)
	query, _ := selector.Query()
	return query
}

func TestBoundedGroupClaimPredicatesUseCorrelatedExists(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name string
		sql  string
		want []string
	}{
		{
			name: "direct membership",
			sql:  renderGroupPredicate(groupHasDirectMembershipForUser(7, now)),
			want: []string{"EXISTS", "user_memberships", "target_id", "groups"},
		},
		{
			name: "department membership",
			sql:  renderGroupPredicate(groupHasDepartmentMembershipForUser(7, now)),
			want: []string{"EXISTS", "user_memberships", "departments", "source_id"},
		},
		{
			name: "effective role",
			sql:  renderGroupPredicate(groupProjectsEffectiveRoleForUser(7, []int{11, 12}, now)),
			want: []string{"EXISTS", "principal_roles", "user_memberships", "departments", "source_id"},
		},
		{
			name: "role users",
			sql:  renderUserPredicate(userHasDirectOrDepartmentRole(9, now)),
			want: []string{"EXISTS", "principal_roles", "user_memberships", "departments", "users"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, fragment := range tt.want {
				if !strings.Contains(tt.sql, fragment) {
					t.Fatalf("query %q does not contain %q", tt.sql, fragment)
				}
			}
		})
	}
}
