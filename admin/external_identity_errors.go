package admin

import (
	"context"
	"errors"

	"github.com/grpc-kit/pkg/errs"
)

var errExternalEmailAlreadyExists = errors.New("external identity email already exists")
var errExternalPhoneAlreadyExists = errors.New("external identity phone number already exists")
var errExternalVerifiedIdentifiersConflict = errors.New("verified external identifiers belong to different users")
var errExternalIdentityAlreadyBound = errors.New("external provider identity is already bound")

// 注：公开错误暂不携带 ErrorInfo reason/domain detail（无运行时消费方，
// 引入条件与治理规则见 adm/docs/roadmap/log/admin-error-output-unification-plan.md §3.4）。
// gRPC code + 双语 message 是当前对外契约。

func externalEmailAlreadyExistsPublicError(ctx context.Context) error {
	return errs.AlreadyExists(ctx).
		WithMessage("the email returned by this authentication provider is already associated with an existing user; sign in to the existing account and bind this provider, or contact an administrator").
		WithMessageZHCN("该认证提供方返回的邮箱已关联其他用户；请先登录已有账号后绑定此认证提供方，或联系管理员处理").
		Err()
}

func externalPhoneAlreadyExistsPublicError(ctx context.Context) error {
	return errs.AlreadyExists(ctx).
		WithMessage("the phone number returned by this authentication provider is already associated with an existing user; sign in to the existing account and bind this provider, or contact an administrator").
		WithMessageZHCN("该认证提供方返回的手机号已关联其他用户；请先登录已有账号后绑定此认证提供方，或联系管理员处理").
		Err()
}

func externalVerifiedIdentifiersConflictPublicError(ctx context.Context) error {
	return errs.AlreadyExists(ctx).
		WithMessage("the verified email and phone number returned by this authentication provider belong to different users; contact an administrator").
		WithMessageZHCN("该认证提供方返回的已验证邮箱和手机号分别属于不同用户，请联系管理员处理").
		Err()
}

func externalIdentityAlreadyBoundPublicError(ctx context.Context) error {
	return errs.AlreadyExists(ctx).
		WithMessage("this authentication provider is already bound to a different identity; contact an administrator").
		WithMessageZHCN("该认证提供方已绑定其他身份，请联系管理员处理").
		Err()
}
