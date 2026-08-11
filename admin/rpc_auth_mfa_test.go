package admin

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/rpc"
)

// newMFATestAPI 构造一个最小化的 KnownAdminAPI（无数据库），用于验证
// current-user MFA 自服务校验前置门。
// 权限校验在 GetLionClient() 之前触发，因此无需真实数据库。
func newMFATestAPI() *KnownAdminAPI {
	return New()
}

func mfaSessionContext(userID int64, sessionID string) context.Context {
	ctx := rpc.ContextWithUserID(context.Background(), userID)
	return rpc.ContextWithTokenClaims(ctx, auth.AccessTokenClaims{
		CommonClaims: auth.CommonClaims{
			RegisteredClaims: jwt.RegisteredClaims{ID: sessionID},
		},
	})
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

func TestSetupCurrentUserMFA_RejectsMissingSubject(t *testing.T) {
	a := newMFATestAPI()
	// context 中无 user_id
	ctx := context.Background()

	_, err := a.SetupCurrentUserMFA(ctx, &adminv1.SetupCurrentUserMFARequest{})
	assertPermissionDenied(t, err)
}

func TestSetupCurrentUserMFA_SubjectPassesGate(t *testing.T) {
	a := newMFATestAPI()
	// 之后会因无数据库而失败（Internal），但绝不应是 PermissionDenied。
	ctx := mfaSessionContext(10, "session-a")

	_, err := a.SetupCurrentUserMFA(ctx, &adminv1.SetupCurrentUserMFARequest{})
	if err == nil {
		t.Fatalf("expected non-nil error (no database), got nil")
	}
	st := errs.FromError(err)
	if st.HTTPStatusCode() == 403 {
		t.Fatalf("owner should pass self-service gate, got 403: %v", err)
	}
}

func TestConfirmCurrentUserMFARejectsChallengeOwnedByAnotherUser(t *testing.T) {
	a := newMFATestAPI()
	challenge, err := a.mfaChallenges.CreateBoundWithTTL(time.Minute, mfaChallengeTypeAdminSetup, 10, "alice", "session-a")
	if err != nil {
		t.Fatalf("create challenge: %v", err)
	}
	if !a.mfaChallenges.SetTempSecret(challenge.ChallengeID, "JBSWY3DPEHPK3PXP") {
		t.Fatal("set challenge secret")
	}

	_, err = a.ConfirmCurrentUserMFA(mfaSessionContext(20, "session-b"), &adminv1.ConfirmCurrentUserMFARequest{
		ChallengeId: challenge.ChallengeID,
		TotpCode:    "123456",
	})
	assertPermissionDenied(t, err)
	if _, ok := a.mfaChallenges.Get(challenge.ChallengeID); !ok {
		t.Fatal("cross-user attempt must not consume the owner's challenge")
	}
}

func TestConfirmCurrentUserMFARejectsDifferentSessionForSameUser(t *testing.T) {
	a := newMFATestAPI()
	challenge, err := a.mfaChallenges.CreateBoundWithTTL(time.Minute, mfaChallengeTypeAdminSetup, 10, "alice", "session-a")
	if err != nil {
		t.Fatalf("create challenge: %v", err)
	}
	if !a.mfaChallenges.SetTempSecret(challenge.ChallengeID, "JBSWY3DPEHPK3PXP") {
		t.Fatal("set challenge secret")
	}

	_, err = a.ConfirmCurrentUserMFA(mfaSessionContext(10, "session-b"), &adminv1.ConfirmCurrentUserMFARequest{
		ChallengeId: challenge.ChallengeID,
		TotpCode:    "123456",
	})
	assertPermissionDenied(t, err)
}

func TestDisableCurrentUserMFA_RejectsMissingSubject(t *testing.T) {
	a := newMFATestAPI()
	ctx := context.Background()

	_, err := a.DisableCurrentUserMFA(ctx, &adminv1.DisableCurrentUserMFARequest{TotpCode: "123456"})
	assertPermissionDenied(t, err)
}

func TestDisableCurrentUserMFA_SubjectPassesGate(t *testing.T) {
	a := newMFATestAPI()
	ctx := mfaSessionContext(10, "session-a")

	_, err := a.DisableCurrentUserMFA(ctx, &adminv1.DisableCurrentUserMFARequest{TotpCode: "123456"})
	if err == nil {
		t.Fatalf("expected non-nil error (no database), got nil")
	}
	st := errs.FromError(err)
	if st.HTTPStatusCode() == 403 {
		t.Fatalf("owner should pass self-service gate, got 403: %v", err)
	}
}
