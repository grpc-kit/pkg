package admin

import (
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	membershipTargetGroup      = int(adminv1.Membership_GROUP)
	membershipTargetDepartment = int(adminv1.Membership_DEPARTMENT)
)

func newMembershipProto(
	id int,
	userID int,
	targetType adminv1.Membership_TargetType,
	targetID int,
	memberRole int,
	memberStatus int,
	memberType int,
	joinedAt *timestamppb.Timestamp,
	expiredAt *timestamppb.Timestamp,
	createdBy int64,
	updatedBy int64,
	createdAt *timestamppb.Timestamp,
	updatedAt *timestamppb.Timestamp,
	description string,
) *adminv1.Membership {
	membership := &adminv1.Membership{
		Id:           int64(id),
		UserId:       int64(userID),
		TargetType:   targetType,
		TargetId:     int64(targetID),
		MemberRole:   adminv1.Membership_Role(memberRole),
		MemberStatus: adminv1.Membership_Status(memberStatus),
		MemberType:   adminv1.Membership_MemberType(memberType),
		CreatedBy:    createdBy,
		UpdatedBy:    updatedBy,
		Description:  description,
	}
	if joinedAt != nil {
		membership.JoinedAt = joinedAt
	}
	if expiredAt != nil {
		membership.ExpiredAt = expiredAt
	}
	if createdAt != nil {
		membership.CreatedAt = createdAt
	}
	if updatedAt != nil {
		membership.UpdatedAt = updatedAt
	}
	return membership
}

func applyMembershipUser(membership *adminv1.Membership, user *lion.Users) {
	if membership == nil || user == nil {
		return
	}
	membership.Username = user.Username
	membership.Nickname = user.Nickname
}

func applyMembershipTargetName(membership *adminv1.Membership, displayName, code string) {
	if membership == nil {
		return
	}
	membership.TargetName = displayName
	if membership.TargetName == "" {
		membership.TargetName = code
	}
}

func membershipTimestamp(value time.Time) *timestamppb.Timestamp {
	if value.IsZero() {
		return nil
	}
	return timestamppb.New(value)
}

func userMembershipToProto(member *lion.UserMemberships) *adminv1.Membership {
	if member == nil {
		return nil
	}
	membership := newMembershipProto(
		member.ID,
		member.UserID,
		adminv1.Membership_TargetType(member.TargetType),
		member.TargetID,
		member.MemberRole,
		member.MemberStatus,
		member.MemberType,
		membershipTimestamp(member.JoinedAt),
		membershipTimestamp(member.ExpiredAt),
		member.CreatedBy,
		member.UpdatedBy,
		membershipTimestamp(member.CreatedAt),
		membershipTimestamp(member.UpdatedAt),
		member.Description,
	)
	if len(member.Metadata) > 0 {
		membership.Metadata = member.Metadata
	}
	applyMembershipUser(membership, member.Edges.LionUsers)
	return membership
}