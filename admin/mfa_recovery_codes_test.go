package admin

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRecoveryCodeSingleUse(t *testing.T) {
	aesKey := []byte("0123456789abcdef0123456789abcdef")
	codes := []string{"a1b2c3d4"}

	encrypted, err := encryptRecoveryCodes(aesKey, codes)
	if err != nil {
		t.Fatalf("encryptRecoveryCodes failed: %v", err)
	}

	nextEncrypted, ok, err := consumeRecoveryCodeEncrypted(aesKey, encrypted, "A1B2-C3D4", time.Now())
	if err != nil {
		t.Fatalf("consumeRecoveryCodeEncrypted first failed: %v", err)
	}
	if !ok {
		t.Fatalf("expected first consume success")
	}

	_, ok, err = consumeRecoveryCodeEncrypted(aesKey, nextEncrypted, "a1b2c3d4", time.Now())
	if err != nil {
		t.Fatalf("consumeRecoveryCodeEncrypted second failed: %v", err)
	}
	if ok {
		t.Fatalf("expected second consume to fail")
	}
}

func TestRecoveryCodeConcurrentCASOnlyOneSuccess(t *testing.T) {
	aesKey := []byte("0123456789abcdef0123456789abcdef")
	codes := []string{"deadbeef"}
	initialEncrypted, err := encryptRecoveryCodes(aesKey, codes)
	if err != nil {
		t.Fatalf("encryptRecoveryCodes failed: %v", err)
	}

	sharedEncrypted := append([]byte(nil), initialEncrypted...)
	var mu sync.Mutex
	var successCount int32

	tryConsumeWithCAS := func(snapshot []byte) {
		nextEncrypted, ok, consumeErr := consumeRecoveryCodeEncrypted(aesKey, snapshot, "deadbeef", time.Now())
		if consumeErr != nil || !ok {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if bytes.Equal(sharedEncrypted, snapshot) {
			sharedEncrypted = nextEncrypted
			atomic.AddInt32(&successCount, 1)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	snapshotA := append([]byte(nil), initialEncrypted...)
	snapshotB := append([]byte(nil), initialEncrypted...)
	go func() {
		defer wg.Done()
		tryConsumeWithCAS(snapshotA)
	}()
	go func() {
		defer wg.Done()
		tryConsumeWithCAS(snapshotB)
	}()
	wg.Wait()

	if got := atomic.LoadInt32(&successCount); got != 1 {
		t.Fatalf("expected exactly one CAS success, got=%d", got)
	}
}

func TestRecoveryCodeCannotConsumeWhenEmpty(t *testing.T) {
	aesKey := []byte("0123456789abcdef0123456789abcdef")

	_, ok, err := consumeRecoveryCodeEncrypted(aesKey, []byte(""), "deadbeef", time.Now())
	if err != nil {
		t.Fatalf("consumeRecoveryCodeEncrypted failed: %v", err)
	}
	if ok {
		t.Fatalf("expected consume fail on empty payload")
	}
}

func TestRecoveryCodeNormalizeWhitespaceAndHyphen(t *testing.T) {
	aesKey := []byte("0123456789abcdef0123456789abcdef")
	codes := []string{"ab12cd34"}

	encrypted, err := encryptRecoveryCodes(aesKey, codes)
	if err != nil {
		t.Fatalf("encryptRecoveryCodes failed: %v", err)
	}

	_, ok, err := consumeRecoveryCodeEncrypted(aesKey, encrypted, " AB12- CD34 ", time.Now())
	if err != nil {
		t.Fatalf("consumeRecoveryCodeEncrypted failed: %v", err)
	}
	if !ok {
		t.Fatalf("expected consume success for normalized recovery code")
	}
}
