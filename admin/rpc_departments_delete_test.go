package admin

import (
	"context"
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
)

func TestDepartmentLifecycleRequestsRejectInvalidID(t *testing.T) {
	a := New()
	t.Cleanup(func() { close(a.mfaChallenges.stopGC) })

	for _, id := range []int64{0, -1} {
		for name, call := range map[string]func() error{
			"delete": func() error {
				_, err := a.DeleteDepartment(context.Background(), &adminv1.DeleteDepartmentRequest{Id: id})
				return err
			},
			"undelete": func() error {
				_, err := a.UndeleteDepartment(context.Background(), &adminv1.UndeleteDepartmentRequest{Id: id})
				return err
			},
			"expunge": func() error {
				_, err := a.ExpungeDepartment(context.Background(), &adminv1.ExpungeDepartmentRequest{Id: id})
				return err
			},
		} {
			t.Run(name, func(t *testing.T) {
				if err := call(); err == nil || errs.FromError(err).HTTPStatusCode() != 400 {
					t.Fatalf("id=%d error=%v, want HTTP 400", id, err)
				}
			})
		}
	}
}

func TestParseListDepartmentsFilterDeletionContract(t *testing.T) {
	tests := []struct {
		name           string
		filter         string
		wantPredicates int
		wantDeleted    bool
		wantErr        bool
	}{
		{name: "deleted only", filter: "deleted_at != null", wantDeleted: true},
		{name: "combined", filter: "deleted_at != null AND department_status = 2", wantPredicates: 1, wantDeleted: true},
		{name: "regular", filter: "department_type = 1", wantPredicates: 1},
		{name: "unknown field", filter: "unknown = 1", wantErr: true},
		{name: "unsupported operator", filter: "deleted_at = null", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			predicates, deletedOnly, err := parseListDepartmentsFilter(tc.filter)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil || len(predicates) != tc.wantPredicates || deletedOnly != tc.wantDeleted {
				t.Fatalf("predicates=%d deletedOnly=%v err=%v", len(predicates), deletedOnly, err)
			}
		})
	}
}
