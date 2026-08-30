package admin

import (
	"crypto/sha256"
	"strings"
	"sync"
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion"
)

func TestParseAndValidateUserFilterCanonicalizes(t *testing.T) {
	rule, err := parseAndValidateUserFilter(" Status=active  and TYPE != employee AND email_verified=TRUE ")
	if err != nil {
		t.Fatalf("parse rule: %v", err)
	}
	want := "status = ACTIVE AND type != EMPLOYEE AND email_verified = true"
	if rule.canonical != want {
		t.Fatalf("canonical = %q, want %q", rule.canonical, want)
	}
	user := &lion.Users{
		UserStatus:    int(adminv1.User_ACTIVE),
		UserType:      int(adminv1.User_ADMIN),
		EmailVerified: true,
	}
	if !rule.matches(user) {
		t.Fatal("expected rule to match user")
	}
}

func TestParseAndValidateUserFilterRejectsUnsupportedSyntax(t *testing.T) {
	tests := []string{
		"",
		"timezone = Asia/Shanghai",
		"locale = en-US",
		"gender = PRIVATE",
		"status >= ACTIVE",
		"status = ACTIVE OR type = ADMIN",
		"status = ACTIVE AND",
		"status = 2",
		"email_verified = 'true'",
		`email_verified = "true"`,
		"metadata.department = ACTIVE",
		"(status = ACTIVE)",
		"NOT status = ACTIVE",
		"status = TYPE_UNSPECIFIED",
		"status = STATUS_UNSPECIFIED",
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			if _, err := parseAndValidateUserFilter(input); err == nil {
				t.Fatalf("expected %q to be rejected", input)
			}
		})
	}
}

func TestParseAndValidateUserFilterLimits(t *testing.T) {
	acceptedConditions := make([]string, maxUserFilterConditions)
	for i := range acceptedConditions {
		acceptedConditions[i] = "status = ACTIVE"
	}
	if _, err := parseAndValidateUserFilter(strings.Join(acceptedConditions, " AND ")); err != nil {
		t.Fatalf("expected exactly %d conditions to be accepted: %v", maxUserFilterConditions, err)
	}

	conditions := make([]string, maxUserFilterConditions+1)
	for i := range conditions {
		conditions[i] = "status = ACTIVE"
	}
	if _, err := parseAndValidateUserFilter(strings.Join(conditions, " AND ")); err == nil {
		t.Fatal("expected condition limit error")
	}
	if _, err := parseAndValidateUserFilter(strings.Repeat("x", maxUserFilterBytes+1)); err == nil {
		t.Fatal("expected byte limit error")
	}
	base := "status = ACTIVE"
	exactLimit := base + strings.Repeat(" ", maxUserFilterBytes-len(base))
	if _, err := parseAndValidateUserFilter(exactLimit); err != nil {
		t.Fatalf("expected exactly %d bytes to be accepted: %v", maxUserFilterBytes, err)
	}
}

func TestParseAndValidateUserFilterExplicitEnumAllowlist(t *testing.T) {
	for _, value := range []string{"CUSTOMER", "MERCHANT", "SUPPLIER", "EMPLOYEE", "ADMIN", "SYSTEM"} {
		if _, err := parseAndValidateUserFilter("type = " + value); err != nil {
			t.Fatalf("expected User.Type %s to be accepted: %v", value, err)
		}
	}
	for _, value := range []string{"PENDING", "ACTIVE", "LOCKED", "DISABLED", "EXPIRED", "SUSPENDED", "DELETED"} {
		if _, err := parseAndValidateUserFilter("status = " + value); err != nil {
			t.Fatalf("expected User.Status %s to be accepted: %v", value, err)
		}
	}
	for _, rule := range []string{
		"type = TYPE_UNSPECIFIED",
		"type = FUTURE_TYPE",
		"status = STATUS_UNSPECIFIED",
		"status = FUTURE_STATUS",
	} {
		if _, err := parseAndValidateUserFilter(rule); err == nil {
			t.Fatalf("expected %q to be rejected", rule)
		}
	}
}

func TestCompiledUserFilterBooleanNotEqual(t *testing.T) {
	rule, err := parseAndValidateUserFilter("email_verified != false AND phone_number_verified != true")
	if err != nil {
		t.Fatalf("parse rule: %v", err)
	}
	if !rule.matches(&lion.Users{EmailVerified: true, PhoneNumberVerified: false}) {
		t.Fatal("expected boolean != rule to match")
	}
	if rule.matches(&lion.Users{EmailVerified: false, PhoneNumberVerified: false}) {
		t.Fatal("expected boolean != rule not to match")
	}
}

func TestCompileUserFilterCacheCanonicalHit(t *testing.T) {
	cache := newUserFilterLRU(8, maxUserFilterBytes)
	first, err := compileUserFilterWithCache(" status=active ", cache, hashUserFilter)
	if err != nil {
		t.Fatalf("compile first rule: %v", err)
	}
	second, err := compileUserFilterWithCache("status = ACTIVE", cache, hashUserFilter)
	if err != nil {
		t.Fatalf("compile canonical rule: %v", err)
	}
	if first != second {
		t.Fatal("expected canonical rule to reuse cached compiled filter")
	}
	if cache.order.Len() != 1 {
		t.Fatalf("cache entries = %d, want 1", cache.order.Len())
	}
}

func TestCompileUserFilterCacheEntryEvictionUsesLRU(t *testing.T) {
	cache := newUserFilterLRU(2, maxUserFilterBytes)
	for _, rule := range []string{"status = ACTIVE", "status = LOCKED"} {
		if _, err := compileUserFilterWithCache(rule, cache, hashUserFilter); err != nil {
			t.Fatalf("compile %q: %v", rule, err)
		}
	}
	if _, err := compileUserFilterWithCache("status = ACTIVE", cache, hashUserFilter); err != nil {
		t.Fatalf("refresh LRU entry: %v", err)
	}
	if _, err := compileUserFilterWithCache("status = DISABLED", cache, hashUserFilter); err != nil {
		t.Fatalf("compile third rule: %v", err)
	}
	if _, ok := cache.get(hashUserFilter("status = LOCKED"), "status = LOCKED"); ok {
		t.Fatal("expected least recently used entry to be evicted")
	}
	if _, ok := cache.get(hashUserFilter("status = ACTIVE"), "status = ACTIVE"); !ok {
		t.Fatal("expected recently used entry to remain cached")
	}
}

func TestCompileUserFilterCacheByteEviction(t *testing.T) {
	firstRule := "status = ACTIVE"
	secondRule := "status = DISABLED"
	cache := newUserFilterLRU(8, len(firstRule)+len(secondRule)-1)
	if _, err := compileUserFilterWithCache(firstRule, cache, hashUserFilter); err != nil {
		t.Fatalf("compile first rule: %v", err)
	}
	if _, err := compileUserFilterWithCache(secondRule, cache, hashUserFilter); err != nil {
		t.Fatalf("compile second rule: %v", err)
	}
	if _, ok := cache.get(hashUserFilter(firstRule), firstRule); ok {
		t.Fatal("expected byte limit to evict oldest entry")
	}
	if cache.bytes > cache.maxSize {
		t.Fatalf("cache bytes = %d, max = %d", cache.bytes, cache.maxSize)
	}
}

func TestCompileUserFilterCacheHashCollisionDoesNotAlias(t *testing.T) {
	cache := newUserFilterLRU(8, maxUserFilterBytes)
	collisionKey := sha256.Sum256([]byte("collision"))
	collidingHash := func(string) [sha256.Size]byte { return collisionKey }
	first, err := compileUserFilterWithCache("status = ACTIVE", cache, collidingHash)
	if err != nil {
		t.Fatalf("compile first rule: %v", err)
	}
	second, err := compileUserFilterWithCache("status = LOCKED", cache, collidingHash)
	if err != nil {
		t.Fatalf("compile colliding rule: %v", err)
	}
	if first == second || second.canonical != "status = LOCKED" {
		t.Fatal("hash collision aliased two different rules")
	}
	cached, ok := cache.get(collisionKey, "status = ACTIVE")
	if !ok || cached != first {
		t.Fatal("hash collision replaced the original cache entry")
	}
}

func TestCompileUserFilterCacheConcurrent(t *testing.T) {
	cache := newUserFilterLRU(8, maxUserFilterBytes)
	const workers = 64
	results := make(chan *compiledUserFilter, workers)
	errors := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			compiled, err := compileUserFilterWithCache("status = ACTIVE", cache, hashUserFilter)
			if err != nil {
				errors <- err
				return
			}
			results <- compiled
		}()
	}
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Fatalf("compile rule concurrently: %v", err)
	}
	var first *compiledUserFilter
	for result := range results {
		if first == nil {
			first = result
			continue
		}
		if result != first {
			t.Fatal("concurrent compile returned duplicate cached objects")
		}
	}
	if cache.order.Len() != 1 {
		t.Fatalf("cache entries = %d, want 1", cache.order.Len())
	}
}

func TestDecodeStoredUserFilterRejectsUnknownFields(t *testing.T) {
	if _, err := decodeStoredUserFilter([]byte(`{"user_filter":"status = ACTIVE","unknown":true}`)); err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestParseAndValidateUserFilterErrorsOmitRawValue(t *testing.T) {
	// §4.1.4：错误信息只含 condition 序号、字段和错误类别，不得回显原始值。
	tests := []string{
		"status = 2",
		"type = SECRET",
		"email_verified = MAYBE",
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, err := parseAndValidateUserFilter(input)
			if err == nil {
				t.Fatalf("expected %q to be rejected", input)
			}
			rawValue := input[strings.LastIndex(input, " ")+1:]
			if strings.Contains(err.Error(), rawValue) {
				t.Fatalf("error %q leaks raw value %q", err, rawValue)
			}
		})
	}
}
