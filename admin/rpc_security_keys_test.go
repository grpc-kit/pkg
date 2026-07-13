package admin

import (
	"testing"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCredentialToProto_BasicFields(t *testing.T) {
	now := time.Now()
	notBefore := now.Add(-time.Hour)
	expiresAt := now.Add(24 * time.Hour)

	row := &lion.Credentials{
		ID:                   42,
		Code:                 "test-cred",
		DisplayName:          "Test Credential",
		Description:          "A test credential",
		CredentialType:       int(adminv1.Credential_KEY_PAIR.Number()),
		CredentialAlgorithm:  int(adminv1.Credential_RSA.Number()),
		CredentialUsage:      int(adminv1.Credential_JWKS.Number()),
		CredentialVisibility: int(adminv1.Visibility_VISIBILITY_RESTRICTED.Number()),
		CredentialStatus:     int(adminv1.Credential_ACTIVE.Number()),
		CredentialSource:     int(adminv1.Credential_SYSTEM.Number()),
		Protected:            true,
		KeyID:                "abc123def456",
		PublicKey:            []byte("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----"),
		Metadata:             map[string]string{"rotation": "30d"},
		CreatedBy:            1,
		UpdatedBy:            2,
		CreatedAt:            now,
		UpdatedAt:            now,
		NotBefore:            &notBefore,
		ExpiresAt:            &expiresAt,
	}

	proto := credentialToProto(row)

	if proto.Id != 42 {
		t.Errorf("expected Id=42, got %d", proto.Id)
	}
	if proto.Code != "test-cred" {
		t.Errorf("expected Code=test-cred, got %s", proto.Code)
	}
	if proto.DisplayName != "Test Credential" {
		t.Errorf("expected DisplayName=Test Credential, got %s", proto.DisplayName)
	}
	if proto.Type != adminv1.Credential_KEY_PAIR {
		t.Errorf("expected Type=KEY_PAIR, got %s", proto.Type)
	}
	if proto.Algorithm != adminv1.Credential_RSA {
		t.Errorf("expected Algorithm=RSA, got %s", proto.Algorithm)
	}
	if proto.Usage != adminv1.Credential_JWKS {
		t.Errorf("expected Usage=JWKS, got %s", proto.Usage)
	}
	if proto.Status != adminv1.Credential_ACTIVE {
		t.Errorf("expected Status=ACTIVE, got %s", proto.Status)
	}
	if proto.Protected != true {
		t.Errorf("expected Protected=true, got %v", proto.Protected)
	}
	if proto.KeyId != "abc123def456" {
		t.Errorf("expected KeyId=abc123def456, got %s", proto.KeyId)
	}
	if proto.CreatedBy != 1 {
		t.Errorf("expected CreatedBy=1, got %d", proto.CreatedBy)
	}
	if len(proto.Metadata) != 1 || proto.Metadata["rotation"] != "30d" {
		t.Errorf("expected Metadata[rotation]=30d, got %v", proto.Metadata)
	}
	if proto.NotBefore == nil {
		t.Error("expected NotBefore to be set")
	}
	if proto.ExpiresAt == nil {
		t.Error("expected ExpiresAt to be set")
	}
}

func TestCredentialToProto_KeyPair_NoSensitiveData(t *testing.T) {
	row := &lion.Credentials{
		ID:             1,
		CredentialType: int(adminv1.Credential_KEY_PAIR.Number()),
		PublicKey:      []byte("public-key-bytes"),
		// These should NOT appear in the proto output
		PrivateKeyEncrypted: []byte("encrypted-private-key"),
	}

	proto := credentialToProto(row)

	kp := proto.GetKeyPair()
	if kp == nil {
		t.Fatal("expected KeyPair key_material to be set")
	}
	if string(kp.PublicKey) != "public-key-bytes" {
		t.Errorf("expected PublicKey=public-key-bytes, got %s", kp.PublicKey)
	}
	if len(kp.PrivateKey) > 0 {
		t.Errorf("PrivateKey should never be returned, got %d bytes", len(kp.PrivateKey))
	}
	if len(kp.Passphrase) > 0 {
		t.Errorf("Passphrase should never be returned, got %d bytes", len(kp.Passphrase))
	}
}

func TestCredentialToProto_APIKey_NoSecret(t *testing.T) {
	row := &lion.Credentials{
		ID:             1,
		CredentialType: int(adminv1.Credential_API_KEY.Number()),
		APIKey:         "ak-1234567890",
		// This should NOT appear in proto output
		APISecretEncrypted: []byte("encrypted-secret"),
	}

	proto := credentialToProto(row)

	ak := proto.GetApiKey()
	if ak == nil {
		t.Fatal("expected ApiKey key_material to be set")
	}
	if ak.ApiKey != "ak-1234567890" {
		t.Errorf("expected ApiKey=ak-1234567890, got %s", ak.ApiKey)
	}
	if len(ak.ApiSecret) > 0 {
		t.Errorf("ApiSecret should never be returned, got %d bytes", len(ak.ApiSecret))
	}
}

func TestCredentialToProto_X509_NoPrivateKey(t *testing.T) {
	row := &lion.Credentials{
		ID:             1,
		CredentialType: int(adminv1.Credential_X509.Number()),
		Certificate:    []byte("cert-bytes"),
		CaChain:        [][]uint8{[]byte("ca1"), []byte("ca2")},
		// These should NOT appear in proto output
		PrivateKeyEncrypted: []byte("encrypted-private-key"),
	}

	proto := credentialToProto(row)

	x := proto.GetX509Data()
	if x == nil {
		t.Fatal("expected X509Data key_material to be set")
	}
	if string(x.Certificate) != "cert-bytes" {
		t.Errorf("expected Certificate=cert-bytes, got %s", x.Certificate)
	}
	if len(x.CaChain) != 2 {
		t.Errorf("expected CaChain len=2, got %d", len(x.CaChain))
	}
	if len(x.PrivateKey) > 0 {
		t.Errorf("PrivateKey should never be returned, got %d bytes", len(x.PrivateKey))
	}
}

func TestCredentialToProto_License_NoKey(t *testing.T) {
	row := &lion.Credentials{
		ID:             1,
		CredentialType: int(adminv1.Credential_LICENSE.Number()),
		Signature:      []byte("sig-bytes"),
		// This should NOT appear in proto output
		LicenseKeyEncrypted: []byte("encrypted-license-key"),
	}

	proto := credentialToProto(row)

	lic := proto.GetLicense()
	if lic == nil {
		t.Fatal("expected License key_material to be set")
	}
	if string(lic.Signature) != "sig-bytes" {
		t.Errorf("expected Signature=sig-bytes, got %s", lic.Signature)
	}
	if len(lic.LicenseKey) > 0 {
		t.Errorf("LicenseKey should never be returned, got %d bytes", len(lic.LicenseKey))
	}
}

func TestCredentialToProto_DeletedAt(t *testing.T) {
	deletedAt := time.Now()

	row := &lion.Credentials{
		ID:        1,
		DeletedAt: &deletedAt,
	}

	proto := credentialToProto(row)

	if proto.DeletedAt == nil {
		t.Fatal("expected DeletedAt to be set")
	}
}

func TestGenerateCredentialCode_AutoGenerate(t *testing.T) {
	code, err := generateCredentialCode("")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(code) < 2 {
		t.Errorf("auto-generated code too short: %s", code)
	}
}

func TestGenerateCredentialCode_ValidCode(t *testing.T) {
	code, err := generateCredentialCode("my-credential")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if code != "my-credential" {
		t.Errorf("expected code=my-credential, got %s", code)
	}
}

func TestGenerateCredentialCode_InvalidCode(t *testing.T) {
	// Code must start with lowercase letter
	_, err := generateCredentialCode("1invalid")
	if err == nil {
		t.Error("expected error for invalid code starting with digit")
	}
}

func TestComputeKeyID_APIKey(t *testing.T) {
	cred := &adminv1.Credential{
		Type: adminv1.Credential_API_KEY,
		KeyMaterial: &adminv1.Credential_ApiKey{
			ApiKey: &adminv1.Credential_ApiKeyData{
				ApiKey: "ak-1234567890",
			},
		},
	}

	keyID := computeKeyID(cred)
	if keyID == "" {
		t.Error("expected non-empty key_id for API_KEY")
	}
	if len(keyID) != 64 {
		t.Errorf("expected 64-char SHA256 hex, got len=%d", len(keyID))
	}
}

func TestComputeKeyID_SymmetricKey(t *testing.T) {
	cred := &adminv1.Credential{
		Type: adminv1.Credential_SYMMETRIC_KEY,
		KeyMaterial: &adminv1.Credential_SymmetricKey{
			SymmetricKey: []byte("my-secret-key"),
		},
	}

	keyID := computeKeyID(cred)
	if keyID == "" {
		t.Error("expected non-empty key_id for SYMMETRIC_KEY")
	}
	if len(keyID) != 64 {
		t.Errorf("expected 64-char SHA256 hex, got len=%d", len(keyID))
	}
}

func TestComputeKeyID_KeyPair(t *testing.T) {
	cred := &adminv1.Credential{
		Type: adminv1.Credential_KEY_PAIR,
		KeyMaterial: &adminv1.Credential_KeyPair{
			KeyPair: &adminv1.Credential_KeyPairData{
				PublicKey: []byte("public-key-bytes"),
			},
		},
	}

	keyID := computeKeyID(cred)
	if keyID == "" {
		t.Error("expected non-empty key_id for KEY_PAIR")
	}
	if len(keyID) != 64 {
		t.Errorf("expected 64-char SHA256 hex, got len=%d", len(keyID))
	}
}

func TestComputeKeyID_Unspecified(t *testing.T) {
	cred := &adminv1.Credential{
		Type: adminv1.Credential_TYPE_UNSPECIFIED,
	}

	keyID := computeKeyID(cred)
	if keyID != "" {
		t.Errorf("expected empty key_id for TYPE_UNSPECIFIED, got %s", keyID)
	}
}

func TestParseListCredentialsFilter_StatusEnum(t *testing.T) {
	preds, err := parseListCredentialsFilter("credential_status=ACTIVE")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(preds) != 1 {
		t.Fatalf("expected 1 predicate, got %d", len(preds))
	}
}

func TestParseListCredentialsFilter_TypeEnum(t *testing.T) {
	preds, err := parseListCredentialsFilter("credential_type=KEY_PAIR")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(preds) != 1 {
		t.Fatalf("expected 1 predicate, got %d", len(preds))
	}
}

func TestParseListCredentialsFilter_Multiple(t *testing.T) {
	preds, err := parseListCredentialsFilter("credential_status=ACTIVE AND credential_type=KEY_PAIR AND code=test-cred")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(preds) != 3 {
		t.Fatalf("expected 3 predicates, got %d", len(preds))
	}
}

func TestParseListCredentialsFilter_NumericValue(t *testing.T) {
	preds, err := parseListCredentialsFilter("credential_status=1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(preds) != 1 {
		t.Fatalf("expected 1 predicate, got %d", len(preds))
	}
}

func TestParseListCredentialsFilter_DisplayNameFold(t *testing.T) {
	preds, err := parseListCredentialsFilter("display_name=JWKS")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(preds) != 1 {
		t.Fatalf("expected 1 predicate, got %d", len(preds))
	}
}

func TestParseListCredentialsFilter_Empty(t *testing.T) {
	preds, err := parseListCredentialsFilter("")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(preds) != 0 {
		t.Fatalf("expected 0 predicates, got %d", len(preds))
	}
}

func TestParseListCredentialsFilter_KeyID(t *testing.T) {
	preds, err := parseListCredentialsFilter("key_id=abc123")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(preds) != 1 {
		t.Fatalf("expected 1 predicate, got %d", len(preds))
	}
}

func TestTimePtr(t *testing.T) {
	now := time.Now()
	ptr := timePtr(now)
	if ptr == nil {
		t.Fatal("expected non-nil pointer")
	}
	if !ptr.Equal(now) {
		t.Errorf("expected %v, got %v", now, *ptr)
	}
}

func TestFirstByte(t *testing.T) {
	if firstByte(nil) != 0 {
		t.Error("expected 0 for empty slice")
	}
	if firstByte([]byte{}) != 0 {
		t.Error("expected 0 for empty slice")
	}
	if firstByte([]byte{0xFF}) != 0xFF {
		t.Error("expected 0xFF")
	}
	if firstByte([]byte{0x30, 0x82}) != 0x30 {
		t.Error("expected 0x30")
	}
}

// Ensure credentials.FieldXxx constants are used (compile-time check)
func TestFieldConstantsExist(t *testing.T) {
	fields := []string{
		credentials.FieldID,
		credentials.FieldCode,
		credentials.FieldKeyID,
		credentials.FieldCredentialType,
		credentials.FieldCredentialStatus,
		credentials.FieldCredentialUsage,
		credentials.FieldCredentialSource,
		credentials.FieldCredentialVisibility,
		credentials.FieldProtected,
		credentials.FieldDisplayName,
		credentials.FieldDescription,
		credentials.FieldAPIKey,
		credentials.FieldPublicKey,
		credentials.FieldCertificate,
		credentials.FieldSignature,
		credentials.FieldNotBefore,
		credentials.FieldExpiresAt,
		credentials.FieldMetadata,
		credentials.FieldCreatedBy,
		credentials.FieldUpdatedBy,
		credentials.FieldCreatedAt,
		credentials.FieldUpdatedAt,
		credentials.FieldDeletedAt,
	}
	for _, f := range fields {
		if f == "" {
			t.Error("expected non-empty field constant")
		}
	}
}

// Test that proto Timestamp fields are properly mapped
func TestCredentialToProto_Timestamps(t *testing.T) {
	now := time.Now()

	row := &lion.Credentials{
		ID:        1,
		CreatedAt: now,
		UpdatedAt: now,
	}

	proto := credentialToProto(row)

	if proto.CreatedAt == nil {
		t.Fatal("expected CreatedAt to be set")
	}
	if proto.UpdatedAt == nil {
		t.Fatal("expected UpdatedAt to be set")
	}
}

func TestIsTokenPersistenceRequest_True(t *testing.T) {
	cred := &adminv1.Credential{
		Type:   adminv1.Credential_SECRET,
		Usage:  adminv1.Credential_AUTH,
		Source: adminv1.Credential_USER,
	}
	if !isTokenPersistenceRequest(cred) {
		t.Error("expected true for SECRET+AUTH+USER")
	}
}

func TestIsTokenPersistenceRequest_WrongType(t *testing.T) {
	cred := &adminv1.Credential{
		Type:   adminv1.Credential_SYMMETRIC_KEY,
		Usage:  adminv1.Credential_AUTH,
		Source: adminv1.Credential_USER,
	}
	if isTokenPersistenceRequest(cred) {
		t.Error("expected false for SYMMETRIC_KEY+AUTH+USER")
	}
}

func TestIsTokenPersistenceRequest_WrongUsage(t *testing.T) {
	cred := &adminv1.Credential{
		Type:   adminv1.Credential_SECRET,
		Usage:  adminv1.Credential_SIGNING,
		Source: adminv1.Credential_USER,
	}
	if isTokenPersistenceRequest(cred) {
		t.Error("expected false for SECRET+SIGNING+USER")
	}
}

func TestIsTokenPersistenceRequest_WrongSource(t *testing.T) {
	cred := &adminv1.Credential{
		Type:   adminv1.Credential_SECRET,
		Usage:  adminv1.Credential_AUTH,
		Source: adminv1.Credential_SYSTEM,
	}
	if isTokenPersistenceRequest(cred) {
		t.Error("expected false for SECRET+AUTH+SYSTEM")
	}
}

func TestDecryptToken_RoundTrip(t *testing.T) {
	aesKey := []byte("0123456789abcdef0123456789abcdef")
	api := New(WithAESKey(aesKey))

	originalToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"
	encrypted, err := crypto.EncryptAES(aesKey, []byte(originalToken))
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decrypted, err := api.decryptToken(encrypted)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if decrypted != originalToken {
		t.Errorf("expected %q, got %q", originalToken, decrypted)
	}
}

func TestDecryptToken_EmptyInput(t *testing.T) {
	aesKey := []byte("0123456789abcdef0123456789abcdef")
	api := New(WithAESKey(aesKey))

	decrypted, err := api.decryptToken(nil)
	if err != nil {
		t.Fatalf("expected no error for empty input, got %v", err)
	}
	if decrypted != "" {
		t.Errorf("expected empty string, got %q", decrypted)
	}
}

// Test that timestamppb import is used (compile-time check)
func TestTimestampPbUsage(t *testing.T) {
	ts := timestamppb.Now()
	if ts == nil {
		t.Fatal("expected non-nil timestamp")
	}
}
