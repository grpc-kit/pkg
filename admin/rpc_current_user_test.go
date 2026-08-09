package admin

import (
	"context"
	"testing"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"google.golang.org/protobuf/proto"
)

func TestGetCurrentUserRequestCannotSelectTargetUser(t *testing.T) {
	descriptor := (&adminv1.GetCurrentUserRequest{}).ProtoReflect().Descriptor()
	if descriptor.Fields().Len() != 0 {
		t.Fatalf("GetCurrentUserRequest has %d fields, want 0", descriptor.Fields().Len())
	}
}

func TestGetCurrentUserRequiresAuthenticatedSubject(t *testing.T) {
	a := New()
	_, err := a.GetCurrentUser(context.Background(), &adminv1.GetCurrentUserRequest{})
	if err == nil {
		t.Fatal("expected authentication error")
	}
	if got := errs.FromError(err).HTTPStatusCode(); got != 401 {
		t.Fatalf("HTTP status = %d, want 401", got)
	}
}

func TestCurrentUserProfileProjectionAndETag(t *testing.T) {
	ctx := context.Background()
	aesKey := []byte("0123456789abcdef0123456789abcdef")
	a := New(WithAESKey(aesKey))
	phone := &adminv1.PhoneNumber{CountryCode: "86", NationalNumber: "13800000000"}
	phoneRaw, err := proto.Marshal(phone)
	if err != nil {
		t.Fatal(err)
	}
	emailEncrypted, err := crypto.EncryptAES(aesKey, []byte("person@example.test"))
	if err != nil {
		t.Fatal(err)
	}
	phoneEncrypted, err := crypto.EncryptAES(aesKey, phoneRaw)
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2025, 1, 1, 0, 0, 0, 0, time.FixedZone("CST", 8*60*60))
	updatedAt := createdAt.Add(time.Hour)
	birthday := time.Date(1990, 2, 3, 0, 0, 0, 0, time.UTC)
	row := &lion.Users{
		ID:                   42,
		Username:             "person",
		Nickname:             "Person",
		Profile:              "profile",
		Picture:              "https://example.test/avatar.png",
		Website:              "https://example.test",
		Timezone:             "Asia/Shanghai",
		Locale:               "zh-CN",
		UserType:             int(adminv1.User_EMPLOYEE),
		UserStatus:           int(adminv1.User_ACTIVE),
		Gender:               int(adminv1.User_PRIVATE),
		Birthdate:            &birthday,
		EmailEncrypted:       emailEncrypted,
		EmailVerified:        true,
		PhoneNumberEncrypted: phoneEncrypted,
		PhoneNumberVerified:  true,
		CreatedAt:            createdAt,
		UpdatedAt:            updatedAt,
		NationalIDEncrypted:  []byte("must-not-be-read"),
		AddressEncrypted:     []byte("must-not-be-read"),
		RealnameEncrypted:    []byte("must-not-be-read"),
		Metadata:             map[string]string{"secret": "must-not-be-read"},
		CreatedBy:            9,
		UpdatedBy:            10,
	}

	profile, err := a.currentUserProfile(ctx, row, true)
	if err != nil {
		t.Fatalf("currentUserProfile: %v", err)
	}
	if profile.GetId() != 42 || profile.GetEmail() != "person@example.test" {
		t.Fatalf("unexpected identity projection: %+v", profile)
	}
	if !proto.Equal(profile.GetPhoneNumber(), phone) || !profile.GetMfaEnabled() {
		t.Fatalf("unexpected phone/MFA projection: %+v", profile)
	}
	if profile.GetEtag() == "" || profile.GetEtag() != currentUserETag(row.ID, updatedAt) {
		t.Fatalf("unexpected etag %q", profile.GetEtag())
	}

	forbidden := map[string]bool{
		"national_id": true, "address": true, "metadata": true, "realname": true,
		"created_by": true, "updated_by": true, "deleted_at": true,
	}
	fields := profile.ProtoReflect().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		if forbidden[string(fields.Get(i).Name())] {
			t.Fatalf("self profile exposes forbidden field %q", fields.Get(i).Name())
		}
	}

	if got := currentUserETag(row.ID, updatedAt.In(time.FixedZone("other", -5*60*60))); got != profile.GetEtag() {
		t.Fatalf("etag must be stable across equivalent time zones: %q != %q", got, profile.GetEtag())
	}
	if got := currentUserETag(row.ID, updatedAt.Add(time.Nanosecond)); got == profile.GetEtag() {
		t.Fatal("etag must change when updated_at changes")
	}
}

func TestCurrentUserProfileRejectsEncryptedFieldFailure(t *testing.T) {
	a := New(WithAESKey([]byte("0123456789abcdef0123456789abcdef")))
	row := &lion.Users{ID: 1, EmailEncrypted: []byte("ciphertext"), CreatedAt: time.Now(), UpdatedAt: time.Now()}
	profile, err := a.currentUserProfile(context.Background(), row, false)
	if err == nil || profile != nil {
		t.Fatalf("expected safe decrypt failure, got profile=%v err=%v", profile, err)
	}
	if got := errs.FromError(err).HTTPStatusCode(); got != 500 {
		t.Fatalf("HTTP status = %d, want 500", got)
	}
}
