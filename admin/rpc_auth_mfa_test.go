package admin

import (
	"context"
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/rpc"
)

// newMFATestAPI 构造一个最小化的 KnownAdminAPI（无数据库），用于验证
// SetupUserMFA / DisableUserMFA 的自服务校验前置门。
// 权限校验在 GetLionClient() 之前触发，因此无需真实数据库。
func newMFATestAPI() *KnownAdminAPI {
	return New()
}

// assertPermissionDenied 断言错误为 403 PermissionDenied。
func assertPermissionDenied(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected PermissionDenied error, got nil")
	}
	st := errs.FromError(err)
	if st.HTTPStatusCode() != 403 {
		t.Fatalf("expected 403, got %d (err: %v)", st.HTTPStatusCode(), err)
	}
}

func TestSetupUserMFA_RejectsNonOwner(t *testing.T) {
	a := newMFATestAPI()
	// JWT 中 operatorID=10，但请求操作 user_id=20
	ctx := rpc.ContextWithUserID(context.Background(), 10)

	_, err := a.SetupUserMFA(ctx, &adminv1.SetupUserMFARequest{UserId: 20})
	assertPermissionDenied(t, err)
}

func TestSetupUserMFA_RejectsMissingUserID(t *testing.T) {
	a := newMFATestAPI()
	// context 中无 user_id
	ctx := context.Background()

	_, err := a.SetupUserMFA(ctx, &adminv1.SetupUserMFARequest{UserId: 20})
	assertPermissionDenied(t, err)
}

func TestSetupUserMFA_OwnerPassesGate(t *testing.T) {
	a := newMFATestAPI()
	// operatorID == req.UserId，自服务校验通过，之后会因无数据库而失败（Internal），
	// 但绝不应是 PermissionDenied，证明校验门已放行。
	ctx := rpc.ContextWithUserID(context.Background(), 10)

	_, err := a.SetupUserMFA(ctx, &adminv1.SetupUserMFARequest{UserId: 10})
	if err == nil {
		t.Fatalf("expected non-nil error (no database), got nil")
	}
	st := errs.FromError(err)
	if st.HTTPStatusCode() == 403 {
		t.Fatalf("owner should pass self-service gate, got 403: %v", err)
	}
}

func TestDisableUserMFA_RejectsNonOwner(t *testing.T) {
	a := newMFATestAPI()
	ctx := rpc.ContextWithUserID(context.Background(), 10)

	_, err := a.DisableUserMFA(ctx, &adminv1.DisableUserMFARequest{UserId: 20, TotpCode: "123456"})
	assertPermissionDenied(t, err)
}

func TestDisableUserMFA_RejectsMissingUserID(t *testing.T) {
	a := newMFATestAPI()
	ctx := context.Background()

	_, err := a.DisableUserMFA(ctx, &adminv1.DisableUserMFARequest{UserId: 20, TotpCode: "123456"})
	assertPermissionDenied(t, err)
}

func TestDisableUserMFA_OwnerPassesGate(t *testing.T) {
	a := newMFATestAPI()
	ctx := rpc.ContextWithUserID(context.Background(), 10)

	_, err := a.DisableUserMFA(ctx, &adminv1.DisableUserMFARequest{UserId: 10, TotpCode: "123456"})
	if err == nil {
		t.Fatalf("expected non-nil error (no database), got nil")
	}
	st := errs.FromError(err)
	if st.HTTPStatusCode() == 403 {
		t.Fatalf("owner should pass self-service gate, got 403: %v", err)
	}
}
