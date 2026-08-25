package admin

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion"
)

func TestNormalizeLDAPUserIDAttributeName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "uid", input: " UID ", want: "uid"},
		{name: "uid number", input: "uidnumber", want: "uidNumber"},
		{name: "entry uuid", input: "ENTRYUUID", want: "entryUUID"},
		{name: "object guid", input: "objectguid", want: "objectGUID"},
		{name: "legacy dn", input: "DN", want: "dn"},
		{name: "custom descriptor", input: "employee-ID;binary", want: "employee-ID;binary"},
		{name: "numeric oid", input: "1.2.840.113556.1.4.2", want: "1.2.840.113556.1.4.2"},
		{name: "empty", input: " ", wantErr: true},
		{name: "invalid", input: "uid name", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeLDAPUserIDAttributeName(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("normalizeLDAPUserIDAttributeName(%q) error = nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeLDAPUserIDAttributeName(%q): %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("normalizeLDAPUserIDAttributeName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestResolveLDAPProviderUserID(t *testing.T) {
	objectGUIDRaw := []byte{
		0x33, 0x22, 0x11, 0x00,
		0x55, 0x44,
		0x77, 0x66,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
	entry := &ldap.Entry{
		DN: "uid=mingqing,cn=users,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "uid", Values: []string{"MingQing"}, ByteValues: [][]byte{[]byte("MingQing")}},
			{Name: "uidNumber", Values: []string{"0010001"}, ByteValues: [][]byte{[]byte("0010001")}},
			{Name: "entryUUID", Values: []string{"550E8400-E29B-41D4-A716-446655440000"}, ByteValues: [][]byte{[]byte("550E8400-E29B-41D4-A716-446655440000")}},
			{Name: "objectGUID", Values: []string{string(objectGUIDRaw)}, ByteValues: [][]byte{objectGUIDRaw}},
		},
	}

	tests := []struct {
		attribute string
		want      string
	}{
		{attribute: "uid", want: "MingQing"},
		{attribute: "uidNumber", want: "10001"},
		{attribute: "entryUUID", want: "550e8400-e29b-41d4-a716-446655440000"},
		{attribute: "objectGUID", want: "00112233-4455-6677-8899-aabbccddeeff"},
		{attribute: "dn", want: entry.DN},
	}

	for _, tt := range tests {
		t.Run(tt.attribute, func(t *testing.T) {
			got, err := resolveLDAPProviderUserID(entry, tt.attribute)
			if err != nil {
				t.Fatalf("resolveLDAPProviderUserID(%q): %v", tt.attribute, err)
			}
			if got != tt.want {
				t.Fatalf("resolveLDAPProviderUserID(%q) = %q, want %q", tt.attribute, got, tt.want)
			}
			if strings.Contains(got, tt.attribute+":") {
				t.Fatalf("provider_user_id %q unexpectedly contains an attribute prefix", got)
			}
		})
	}
}

func TestResolveLDAPProviderUserIDRejectsMissingAndMultipleValues(t *testing.T) {
	missing := &ldap.Entry{DN: "uid=test,dc=example,dc=com"}
	if _, err := resolveLDAPProviderUserID(missing, "uid"); err == nil {
		t.Fatal("missing uid must fail")
	}

	multiple := &ldap.Entry{
		DN: "uid=test,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "uid", Values: []string{"first", "second"}},
		},
	}
	if _, err := resolveLDAPProviderUserID(multiple, "uid"); err == nil {
		t.Fatal("multi-valued uid must fail")
	}
}

func TestLDAPProviderConfigPresence(t *testing.T) {
	provider := &adminv1.AuthProvider{
		Type:   adminv1.AuthProvider_LDAP,
		Config: &adminv1.AuthProvider_LdapConfig{LdapConfig: &adminv1.LdapConfig{}},
	}
	if err := prepareLDAPProviderConfigForCreate(context.Background(), provider); err != nil {
		t.Fatalf("prepareLDAPProviderConfigForCreate: %v", err)
	}
	if provider.GetLdapConfig().UserIdAttribute == nil || provider.GetLdapConfig().GetUserIdAttribute() != "uid" {
		t.Fatalf("new LDAP provider user_id_attribute = %#v, want explicit uid", provider.GetLdapConfig().UserIdAttribute)
	}

	configJSON, _, err := protoToDBConfig(provider, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("protoToDBConfig: %v", err)
	}
	var stored ldapConfigData
	if err := json.Unmarshal(configJSON, &stored); err != nil {
		t.Fatalf("unmarshal LDAP config: %v", err)
	}
	if stored.UserIDAttribute == nil || *stored.UserIDAttribute != "uid" {
		t.Fatalf("stored user_id_attribute = %#v, want explicit uid", stored.UserIDAttribute)
	}

	legacy := ldapConfigData{}
	if got := effectiveLDAPUserIDAttribute(&legacy); got != "dn" {
		t.Fatalf("legacy effective attribute = %q, want dn", got)
	}
}

func TestPrepareLDAPProviderConfigForUpdate(t *testing.T) {
	explicitUID := "uid"
	existing := &lion.AuthProviders{
		ID:           17,
		ProviderType: int(adminv1.AuthProvider_LDAP.Number()),
		Config:       json.RawMessage(`{"user_id_attribute":"uid"}`),
	}

	t.Run("absent preserves stored presence", func(t *testing.T) {
		requested := &adminv1.AuthProvider{
			Config: &adminv1.AuthProvider_LdapConfig{LdapConfig: &adminv1.LdapConfig{}},
		}
		if err := prepareLDAPProviderConfigForUpdate(context.Background(), nil, existing, requested); err != nil {
			t.Fatalf("prepareLDAPProviderConfigForUpdate: %v", err)
		}
		if requested.GetLdapConfig().UserIdAttribute == nil || *requested.GetLdapConfig().UserIdAttribute != explicitUID {
			t.Fatalf("request user_id_attribute = %#v, want preserved uid", requested.GetLdapConfig().UserIdAttribute)
		}
	})

	t.Run("legacy missing remains absent", func(t *testing.T) {
		legacy := &lion.AuthProviders{
			ID:           18,
			ProviderType: int(adminv1.AuthProvider_LDAP.Number()),
			Config:       json.RawMessage(`{"username_attribute":"uid"}`),
		}
		requested := &adminv1.AuthProvider{
			Config: &adminv1.AuthProvider_LdapConfig{LdapConfig: &adminv1.LdapConfig{}},
		}
		if err := prepareLDAPProviderConfigForUpdate(context.Background(), nil, legacy, requested); err != nil {
			t.Fatalf("prepareLDAPProviderConfigForUpdate: %v", err)
		}
		if requested.GetLdapConfig().UserIdAttribute != nil {
			t.Fatalf("legacy request user_id_attribute = %#v, want absent", requested.GetLdapConfig().UserIdAttribute)
		}
	})

}
