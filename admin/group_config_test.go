package admin

import (
	"context"
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
	tests := []*adminv1.Group{
		{
			Type: adminv1.Group_EXTERNAL,
			Config: &adminv1.Group_DynamicConfig_{DynamicConfig: &adminv1.Group_DynamicConfig{
				UserFilter: "status = ACTIVE",
			}},
		},
		{
			Type:       adminv1.Group_DYNAMIC,
			MaxMembers: 1,
			Config: &adminv1.Group_DynamicConfig_{DynamicConfig: &adminv1.Group_DynamicConfig{
				UserFilter: "status = ACTIVE",
			}},
		},
		{Type: adminv1.Group_PROJECT, ParentId: 1},
	}
	for _, group := range tests {
		if _, err := validateGroupTypeConfig(context.Background(), nil, group, false); err == nil {
			t.Fatalf("expected group %+v to be rejected", group)
		}
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
