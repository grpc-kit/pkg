package admin

import (
	"context"
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/rpc"
)

func TestUserLifecycleRequestsRejectInvalidID(t *testing.T) {
	a := New()
	t.Cleanup(func() { close(a.mfaChallenges.stopGC) })

	for _, id := range []int64{0, -1} {
		for name, call := range map[string]func() error{
			"delete": func() error {
				_, err := a.DeleteUser(context.Background(), &adminv1.DeleteUserRequest{Id: id})
				return err
			},
			"undelete": func() error {
				_, err := a.UndeleteUser(context.Background(), &adminv1.UndeleteUserRequest{Id: id})
				return err
			},
			"expunge": func() error {
				_, err := a.ExpungeUser(context.Background(), &adminv1.ExpungeUserRequest{Id: id})
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

func TestDeleteUserRejectsSelfBeforeDatabaseAccess(t *testing.T) {
	a := New()
	t.Cleanup(func() { close(a.mfaChallenges.stopGC) })
	ctx := rpc.ContextWithUserID(context.Background(), 42)
	_, err := a.DeleteUser(ctx, &adminv1.DeleteUserRequest{Id: 42})
	if err == nil || errs.FromError(err).HTTPStatusCode() != 400 {
		t.Fatalf("DeleteUser self error=%v, want HTTP 400", err)
	}
}

func TestListUsersDeletedOnlyFilterContract(t *testing.T) {
	tests := []struct {
		name string
		req  *adminv1.ListUsersRequest
		want bool
		code int
	}{
		{name: "empty", req: &adminv1.ListUsersRequest{}, want: false},
		{name: "recycle bin", req: &adminv1.ListUsersRequest{ShowDeleted: true, Filter: "deleted_at != null"}, want: true},
		{name: "deleted without include", req: &adminv1.ListUsersRequest{Filter: "deleted_at != null"}, code: 400},
		{name: "unsupported", req: &adminv1.ListUsersRequest{ShowDeleted: true, Filter: "status = ACTIVE"}, code: 400},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := listUsersDeletedOnly(tc.req)
			if tc.code != 0 {
				if err == nil || errs.FromError(err).HTTPStatusCode() != tc.code {
					t.Fatalf("error=%v, want HTTP %d", err, tc.code)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got=%v err=%v, want=%v", got, err, tc.want)
			}
		})
	}
}
