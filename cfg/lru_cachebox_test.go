package cfg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	pklogging "github.com/grpc-kit/pkg/logging"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/trace"
)

type cacheLogContextKey struct{}

type redisCacheFake struct {
	redis.UniversalClient
	getValue string
	getErr   error
	setErr   error
}

func (f *redisCacheFake) Get(ctx context.Context, key string) *redis.StringCmd {
	cmd := redis.NewStringCmd(ctx, "get", key)
	cmd.SetVal(f.getValue)
	cmd.SetErr(f.getErr)
	return cmd
}

func (f *redisCacheFake) Set(ctx context.Context, key string, value any, expiration time.Duration) *redis.StatusCmd {
	cmd := redis.NewStatusCmd(ctx, "set", key, value, expiration)
	cmd.SetVal("OK")
	cmd.SetErr(f.setErr)
	return cmd
}

func decodeCacheLog(t *testing.T, output *bytes.Buffer) map[string]any {
	t.Helper()
	if got := strings.Count(output.String(), "\n"); got != 1 {
		t.Fatalf("JSON line count = %d, want 1; output=%q", got, output.String())
	}
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode JSON log: %v", err)
	}
	return record
}

func newTestMemoryCache() *memoryCache {
	return newMemoryCache(pklogging.Fallback(), 100)
}

func TestNewRedisCacheInvalidTLSLogsThenPanics(t *testing.T) {
	var output bytes.Buffer
	logger := pklogging.New(&output, pklogging.FormatJSON, &slog.HandlerOptions{Level: slog.LevelDebug})
	config := RedisCacheboxConfig{TLSClientConfig: &TLSConfig{CertFile: "client.crt"}}
	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1, 2, 3},
		SpanID:  trace.SpanID{4, 5, 6},
	})
	ctx := trace.ContextWithSpanContext(t.Context(), spanContext)
	ctx = context.WithValue(ctx, cacheLogContextKey{}, "context-cache-secret")

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		newRedisCache(ctx, logger, config)
	}()

	wantPanic := "redis tls config error: client cert file \"client.crt\" specified without client key file\n"
	if recovered != wantPanic {
		t.Fatalf("panic value = %#v, want %q", recovered, wantPanic)
	}

	record := decodeCacheLog(t, &output)
	for key, want := range map[string]string{
		"level":    "panic",
		"msg":      "redis TLS configuration failed",
		"trace_id": spanContext.TraceID().String(),
		"span_id":  spanContext.SpanID().String(),
	} {
		if got := record[key]; got != want {
			t.Errorf("%s = %v, want %q", key, got, want)
		}
	}
	for _, forbidden := range []string{"client.crt", "context-cache-secret", "client cert file"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("sensitive value %q leaked into panic log: %q", forbidden, output.String())
		}
	}
	for _, key := range []string{"event", "error_kind"} {
		if _, exists := record[key]; exists {
			t.Errorf("unexpected structured field %q in panic log", key)
		}
	}
}

func TestRedisCacheLogsDoNotExposeKeysOrErrors(t *testing.T) {
	const cacheKey = "tenant:credential:cache-key-sensitive"
	writeErr := errors.New("redis://user:password@cache-sensitive.example:6379")

	tests := []struct {
		name        string
		client      *redisCacheFake
		run         func(context.Context, *redisCache) bool
		wantMessage string
		forbidden   []string
	}{
		{
			name:   "base64 decode",
			client: &redisCacheFake{getValue: "not-base64"},
			run: func(ctx context.Context, cache *redisCache) bool {
				var value string
				return cache.GetStructValue(ctx, cacheKey, &value)
			},
			wantMessage: "redis cache base64 decoding failed",
		},
		{
			name:   "gob decode",
			client: &redisCacheFake{getValue: base64.StdEncoding.EncodeToString([]byte("invalid-gob-sensitive"))},
			run: func(ctx context.Context, cache *redisCache) bool {
				var value string
				return cache.GetStructValue(ctx, cacheKey, &value)
			},
			wantMessage: "redis cache gob decoding failed",
			forbidden:   []string{"invalid-gob-sensitive"},
		},
		{
			name:        "encode without TTL",
			client:      &redisCacheFake{},
			run:         func(ctx context.Context, cache *redisCache) bool { return cache.SetValue(ctx, cacheKey, func() {}) },
			wantMessage: "redis cache value encoding failed",
		},
		{
			name:        "write without TTL",
			client:      &redisCacheFake{setErr: writeErr},
			run:         func(ctx context.Context, cache *redisCache) bool { return cache.SetValue(ctx, cacheKey, "value") },
			wantMessage: "redis cache write failed",
			forbidden:   []string{writeErr.Error()},
		},
		{
			name:   "encode with TTL",
			client: &redisCacheFake{},
			run: func(ctx context.Context, cache *redisCache) bool {
				return cache.SetValueWithTTL(ctx, cacheKey, func() {}, time.Minute)
			},
			wantMessage: "redis cache value encoding failed",
		},
		{
			name:   "write with TTL",
			client: &redisCacheFake{setErr: writeErr},
			run: func(ctx context.Context, cache *redisCache) bool {
				return cache.SetValueWithTTL(ctx, cacheKey, "value", time.Minute)
			},
			wantMessage: "redis cache write failed",
			forbidden:   []string{writeErr.Error()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			logger := pklogging.New(&output, pklogging.FormatJSON, nil)
			cache := &redisCache{logger: logger, cache: tt.client}
			if tt.run(t.Context(), cache) {
				t.Fatal("cache operation = true, want false")
			}

			record := decodeCacheLog(t, &output)
			for key, want := range map[string]string{
				"level": "error",
				"msg":   tt.wantMessage,
			} {
				if got := record[key]; got != want {
					t.Errorf("%s = %v, want %q", key, got, want)
				}
			}
			for _, key := range []string{"event", "error_kind", "stage", "ttl_enabled"} {
				if _, exists := record[key]; exists {
					t.Errorf("unexpected structured field %q in cache log", key)
				}
			}
			for _, forbidden := range append([]string{cacheKey}, tt.forbidden...) {
				if strings.Contains(output.String(), forbidden) {
					t.Fatalf("sensitive value %q leaked into cache log: %q", forbidden, output.String())
				}
			}
		})
	}
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
