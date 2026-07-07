package admin

import (
	"context"
	"sort"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/rolepolicies"
	"github.com/grpc-kit/pkg/lion/roles"
)

// buildRoleDescendantClosure 计算每个角色的下层角色闭包，结果包含角色自身。
func buildRoleDescendantClosure(ctx context.Context, db *lion.Client) (map[int][]int, error) {
	roleList, err := db.Roles.Query().Select(roles.FieldID, roles.FieldParentID).All(ctx)
	if err != nil {
		return nil, err
	}

	childrenByParent := make(map[int][]int)
	roleIDs := make([]int, 0, len(roleList))
	for _, role := range roleList {
		roleIDs = append(roleIDs, role.ID)
		childrenByParent[role.ParentID] = append(childrenByParent[role.ParentID], role.ID)
	}

	closure := make(map[int][]int, len(roleList))
	var visit func(int) []int
	visit = func(roleID int) []int {
		if ids, ok := closure[roleID]; ok {
			return ids
		}
		ids := []int{roleID}
		for _, childID := range childrenByParent[roleID] {
			ids = append(ids, visit(childID)...)
		}
		sort.Ints(ids)
		closure[roleID] = compactSortedInts(ids)
		return closure[roleID]
	}

	for _, roleID := range roleIDs {
		visit(roleID)
	}
	return closure, nil
}

// listPoliciesForRoles 根据角色集合及其下层闭包返回启用状态的策略实体。
func listPoliciesForRoles(ctx context.Context, db *lion.Client, roleIDs []int) ([]*lion.Policies, error) {
	if len(roleIDs) == 0 {
		return []*lion.Policies{}, nil
	}

	closure, err := buildRoleDescendantClosure(ctx, db)
	if err != nil {
		return nil, err
	}

	expanded := make([]int, 0, len(roleIDs))
	for _, roleID := range compactSortedInts(append([]int(nil), roleIDs...)) {
		expanded = append(expanded, closure[roleID]...)
	}
	expanded = compactSortedInts(expanded)
	if len(expanded) == 0 {
		return []*lion.Policies{}, nil
	}

	bindings, err := db.RolePolicies.Query().
		Where(rolepolicies.RoleIDIn(expanded...)).
		WithLionPolicies().
		All(ctx)
	if err != nil {
		return nil, err
	}

	policyByID := make(map[int]*lion.Policies)
	for _, binding := range bindings {
		policy := binding.Edges.LionPolicies
		if policy == nil || policy.PolicyStatus != int(adminv1.Policy_ENABLED) {
			continue
		}
		policyByID[policy.ID] = policy
	}

	result := make([]*lion.Policies, 0, len(policyByID))
	for _, policy := range policyByID {
		result = append(result, policy)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return result, nil
}

func compactSortedInts(ids []int) []int {
	if len(ids) == 0 {
		return ids
	}
	sort.Ints(ids)
	out := ids[:1]
	for _, id := range ids[1:] {
		if id != out[len(out)-1] {
			out = append(out, id)
		}
	}
	return out
}
