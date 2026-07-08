package cfg

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func newTestMemoryCache() *memoryCache {
	logger := logrus.NewEntry(logrus.New())
	return newMemoryCache(logger, 100)
}

func TestMemoryCache_SetValue_NeverExpires(t *testing.T) {
	cache := newTestMemoryCache()
	ctx := context.Background()

	cache.SetValue(ctx, "key1", "value1")

	var result string
	if !cache.GetStructValue(ctx, "key1", &result) {
		t.Fatal("expected to get value from cache")
	}
	if result != "value1" {
		t.Fatalf("expected value1, got %v", result)
	}
}

func TestMemoryCache_SetValueWithTTL_BeforeExpiry(t *testing.T) {
	cache := newTestMemoryCache()
	ctx := context.Background()

	cache.SetValueWithTTL(ctx, "key1", "value1", 5*time.Second)

	var result string
	if !cache.GetStructValue(ctx, "key1", &result) {
		t.Fatal("expected to get value before TTL expires")
	}
	if result != "value1" {
		t.Fatalf("expected value1, got %v", result)
	}
}

func TestMemoryCache_SetValueWithTTL_AfterExpiry(t *testing.T) {
	cache := newTestMemoryCache()
	ctx := context.Background()

	cache.SetValueWithTTL(ctx, "key1", "value1", 100*time.Millisecond)

	time.Sleep(200 * time.Millisecond)

	var result string
	if cache.GetStructValue(ctx, "key1", &result) {
		t.Fatal("expected cache miss after TTL expires")
	}
}

func TestMemoryCache_SetValueWithTTL_ExpiredEntryRemoved(t *testing.T) {
	cache := newTestMemoryCache()
	ctx := context.Background()

	cache.SetValueWithTTL(ctx, "key1", "value1", 100*time.Millisecond)

	time.Sleep(200 * time.Millisecond)

	var result string
	cache.GetStructValue(ctx, "key1", &result)

	// After lazy deletion, the entry should be removed from LRU cache
	// so a subsequent Get should also miss
	if cache.GetStructValue(ctx, "key1", &result) {
		t.Fatal("expected expired entry to be removed after first access")
	}
}

func TestMemoryCache_SetValueWithTTL_ZeroDuration(t *testing.T) {
	cache := newTestMemoryCache()
	ctx := context.Background()

	cache.SetValueWithTTL(ctx, "key1", "value1", 0)

	// ttl=0 should mean never expire
	var result string
	if !cache.GetStructValue(ctx, "key1", &result) {
		t.Fatal("expected value to persist with zero TTL")
	}
	if result != "value1" {
		t.Fatalf("expected value1, got %v", result)
	}
}

func TestMemoryCache_Remove(t *testing.T) {
	cache := newTestMemoryCache()
	ctx := context.Background()

	cache.SetValue(ctx, "key1", "value1")
	cache.Remove(ctx, "key1")

	var result string
	if cache.GetStructValue(ctx, "key1", &result) {
		t.Fatal("expected cache miss after remove")
	}
}
