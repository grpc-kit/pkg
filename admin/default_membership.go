package admin

import (
	"context"
	"log/slog"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion"
	pklogging "github.com/grpc-kit/pkg/logging"
)

// ensureUnassignedDepartmentMembership 在同一事务内为首次建档的外部登录用户
// 补建「待分配部门」(unassigned) 的成员关系，取值与 CreateUser 默认归属一致：
// MEMBER/ACTIVE/PRIMARY；系统建档不写 CreatedBy/UpdatedBy（保持默认 0，
// 与初始化种子的 admin 部门成员关系一致）。
// 待分配部门缺失时记录告警并跳过（返回 nil），不阻断登录建档；
// 其余错误原样返回，由调用方决定回滚。
// 仅限“新建用户”分支调用：UNIQUE(user_id,target_type,target_id) 与
// 单 PRIMARY 部分唯一索引保证重复调用不会产生冲突数据。
func (s *socialUsers) ensureUnassignedDepartmentMembership(ctx context.Context, tx *lion.Tx, userID int) error {
	unassignedDept, err := queryBuiltinDepartment(
		ctx,
		tx,
		seedDepartmentCode(adminv1.DepartmentCode_DEPARTMENT_CODE_UNASSIGNED),
	)
	if err != nil {
		if lion.IsNotFound(err) {
			pklogging.OrFallback(s.logger).LogAttrs(ctx, slog.LevelWarn,
				"Unassigned department missing; skip default department membership",
				slog.String("event", "unassigned_department_missing"),
				slog.String("provider", s.ProviderName),
				slog.Int("user_id", userID),
			)
			return nil
		}
		return err
	}

	return tx.UserMemberships.Create().
		SetUserID(userID).
		SetTargetType(membershipTargetDepartment).
		SetTargetID(unassignedDept.ID).
		SetMemberRole(int(adminv1.Membership_MEMBER)).
		SetMemberStatus(int(adminv1.Membership_ACTIVE)).
		SetMemberType(int(adminv1.Membership_PRIMARY)).
		Exec(ctx)
}
