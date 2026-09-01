package admin

import (
	"context"
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
)

func TestDeleteUserMFARejectsInvalidUserID(t *testing.T) {
	a := New()
	t.Cleanup(func() { close(a.mfaChallenges.stopGC) })

	for _, req := range []*adminv1.DeleteUserMFARequest{nil, {UserId: 0}, {UserId: -1}} {
		_, err := a.DeleteUserMFA(context.Background(), req)
		if err == nil || errs.FromError(err).HTTPStatusCode() != 400 {
			t.Fatalf("DeleteUserMFA(%v) error = %v, want HTTP 400", req, err)
		}
	}
}
