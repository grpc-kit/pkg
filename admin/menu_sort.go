package admin

import "fmt"

const (
	adminMenuCode = "admin"

	defaultMenuSortOrder         = 100
	adminMenuSortPersonal        = 100
	adminMenuSortBusinessMin     = 200
	adminMenuSortBusinessDefault = 500
	adminMenuSortBusinessMax     = 800
	adminMenuSortObservability   = 900
	adminMenuSortDevtools        = 910
	adminMenuSortSettings        = 990
	maxMenuSortOrder             = 9999
)

const (
	adminSettingsMenuSortUsers       = 100
	adminSettingsMenuSortDepartments = 200
	adminSettingsMenuSortGroups      = 300
	adminSettingsMenuSortRoles       = 400
	adminSettingsMenuSortPolicies    = 500
	adminSettingsMenuSortAuth        = 600
	adminSettingsMenuSortMenus       = 700
	adminSettingsMenuSortGovernance  = 800
	adminSettingsMenuSortConfig      = 900
)

// normalizeMenuSortOrder applies the reserved ordering contract for direct
// children of the admin platform menu. Other levels keep their own local
// 1..9999 ordering space.
func normalizeMenuSortOrder(parentCode string, requested int) (int, error) {
	if requested < 0 || requested > maxMenuSortOrder {
		return 0, fmt.Errorf("sort_order must be between 1 and %d", maxMenuSortOrder)
	}
	if parentCode == adminMenuCode {
		if requested == 0 {
			return adminMenuSortBusinessDefault, nil
		}
		if requested < adminMenuSortBusinessMin || requested > adminMenuSortBusinessMax {
			return 0, fmt.Errorf(
				"sort_order must be between %d and %d for menus directly under admin",
				adminMenuSortBusinessMin,
				adminMenuSortBusinessMax,
			)
		}
		return requested, nil
	}
	if requested == 0 {
		return defaultMenuSortOrder, nil
	}
	return requested, nil
}
