package admin

import (
	"context"
	"strings"
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion"
)

func TestValidateGroupTypeConfigDynamic(t *testing.T) {
	group := &adminv1.Group{
		Type:   adminv1.Group_DYNAMIC,
		Status: adminv1.Group_ACTIVE,
		Config: &adminv1.Group_DynamicConfig_{DynamicConfig: &adminv1.Group_DynamicConfig{
			UserFilter: " STATUS=active ",
		}},
	}
	validated, err := validateGroupTypeConfig(context.Background(), nil, group, false)
	if err != nil {
		t.Fatalf("validate dynamic group: %v", err)
	}
	if got, want := string(validated.config), `{"user_filter":"status = ACTIVE"}`; got != want {
		t.Fatalf("config = %s, want %s", got, want)
	}
}

func TestValidateGroupTypeConfigRejectsCrossBranchAndMaxMembers(t *testing.T) {
	tests := []struct {
		name        string
		group       *adminv1.Group
		allowSystem bool
	}{
		{name: "nil group"},
		{name: "unspecified type", group: &adminv1.Group{}},
		{name: "negative max members", group: &adminv1.Group{Type: adminv1.Group_PROJECT, MaxMembers: -1}},
		{name: "parent before hierarchy enabled", group: &adminv1.Group{Type: adminv1.Group_PROJECT, ParentId: 1}},
		{
			name: "manual group with config",
			group: &adminv1.Group{
				Type: adminv1.Group_EXTERNAL,
				Config: &adminv1.Group_DynamicConfig_{DynamicConfig: &adminv1.Group_DynamicConfig{
					UserFilter: "status = ACTIVE",
				}},
			},
		},
		{name: "dynamic without config", group: &adminv1.Group{Type: adminv1.Group_DYNAMIC}},
		{
			name: "dynamic max members",
			group: &adminv1.Group{
				Type:       adminv1.Group_DYNAMIC,
				MaxMembers: 1,
				Config: &adminv1.Group_DynamicConfig_{DynamicConfig: &adminv1.Group_DynamicConfig{
					UserFilter: "status = ACTIVE",
				}},
			},
		},
		{
			name: "system through public API",
			group: &adminv1.Group{
				Type: adminv1.Group_SYSTEM,
				Config: &adminv1.Group_SystemConfig_{SystemConfig: &adminv1.Group_SystemConfig{
					UserFilter: "status = ACTIVE",
				}},
			},
		},
		{name: "system seed without config", group: &adminv1.Group{Type: adminv1.Group_SYSTEM}, allowSystem: true},
		{
			name: "system seed max members",
			group: &adminv1.Group{
				Type:       adminv1.Group_SYSTEM,
				MaxMembers: 1,
				Config: &adminv1.Group_SystemConfig_{SystemConfig: &adminv1.Group_SystemConfig{
					UserFilter: "status = ACTIVE",
				}},
			},
			allowSystem: true,
		},
		{name: "department without config", group: &adminv1.Group{Type: adminv1.Group_DEPARTMENT}},
		{
			name: "department max members",
			group: &adminv1.Group{
				Type:       adminv1.Group_DEPARTMENT,
				MaxMembers: 1,
				Config: &adminv1.Group_DepartmentConfig_{DepartmentConfig: &adminv1.Group_DepartmentConfig{
					DepartmentId: 1,
				}},
			},
		},
		{name: "role without config", group: &adminv1.Group{Type: adminv1.Group_ROLE}},
		{
			name: "role max members",
			group: &adminv1.Group{
				Type:       adminv1.Group_ROLE,
				MaxMembers: 1,
				Config: &adminv1.Group_RoleConfig_{RoleConfig: &adminv1.Group_RoleConfig{
					RoleId: 1,
				}},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validateGroupTypeConfig(context.Background(), nil, test.group, test.allowSystem); err == nil {
				t.Fatalf("expected group %+v to be rejected", test.group)
			}
		})
	}
}

func TestValidateGroupTypeConfigAcceptsNonDatabaseBranches(t *testing.T) {
	tests := []struct {
		name        string
		group       *adminv1.Group
		allowSystem bool
	}{
		{name: "project", group: &adminv1.Group{Type: adminv1.Group_PROJECT, MaxMembers: 10}},
		{name: "external", group: &adminv1.Group{Type: adminv1.Group_EXTERNAL, MaxMembers: 10}},
		{name: "community", group: &adminv1.Group{Type: adminv1.Group_COMMUNITY, MaxMembers: 10}},
		{
			name: "dynamic",
			group: &adminv1.Group{
				Type: adminv1.Group_DYNAMIC,
				Config: &adminv1.Group_DynamicConfig_{DynamicConfig: &adminv1.Group_DynamicConfig{
					UserFilter: "status = ACTIVE",
				}},
			},
		},
		{
			name: "system seed",
			group: &adminv1.Group{
				Type: adminv1.Group_SYSTEM,
				Config: &adminv1.Group_SystemConfig_{SystemConfig: &adminv1.Group_SystemConfig{
					UserFilter: "status = ACTIVE",
				}},
			},
			allowSystem: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validateGroupTypeConfig(context.Background(), nil, test.group, test.allowSystem); err != nil {
				t.Fatalf("validate group: %v", err)
			}
		})
	}
}

func TestPopulateGroupProtoConfigRejectsCorruptStorage(t *testing.T) {
	row := &lion.Groups{
		ID:        7,
		GroupType: int(adminv1.Group_DYNAMIC),
		Config:    []byte(`{"user_filter":"status = ACTIVE","extra":true}`),
	}
	if err := populateGroupProtoConfig(&adminv1.Group{}, row); err == nil {
		t.Fatal("expected corrupt config to be rejected")
	}
}

func TestGroupToProtoCorruptConfigErrorIsGeneric(t *testing.T) {
	// §4.1/§4.1.4：读取路径对存量配置损坏只暴露组 ID 与错误类别，
	// 不得透传存量规则内容（字段名、condition 序号、原始值）。
	row := &lion.Groups{
		ID:        7,
		GroupType: int(adminv1.Group_DYNAMIC),
		Config:    []byte(`{"user_filter":"status = 2"}`),
	}
	_, err := groupToProto(row, false)
	if err == nil {
		t.Fatal("expected corrupt config to be rejected")
	}
	if !strings.Contains(err.Error(), "group 7") {
		t.Fatalf("error %q should identify the group id", err)
	}
	for _, leaked := range []string{"2", "condition", "status"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("error %q leaks stored rule content %q", err, leaked)
		}
	}
}
