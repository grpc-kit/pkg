package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Phase 1 P9：Reload + HTTP handler + 指标 行为测试。
//
// 设计取舍：
//   - 不并发跑 t.Parallel —— 三个指标是包级单例，并发会让 testutil.ToFloat64
//     断言互相串扰；保持顺序执行换断言稳定性。
//   - 不直接调 Allow —— Allow 内部需要 envoy 上下文（c.envoy.getCheckRequest(ctx)
//     非 nil），构造门槛高且与 P9 目的（验 Reload 安全 + 指标）无关。改为直接调
//     c.mergeGrpcKitInput 与等价的 c.mu.RLock 读路径触达内部入口。
//   - 失败路径用"会失败的 DataProvider"触发 initOPARego 中段 return err。
//   - 并发安全断言"无 panic"，真竞争靠 `go test -race` 暴露（CI 默认开 -race）。

// newReloadableClient 构造一个最小可工作的 OPARego Client。
// 不挂 DataProvider；测试中按需替换 c.config.OPARego.DataProvider 触发不同路径。
func newReloadableClient(t *testing.T) *Client {
	t.Helper()
	ctx := context.Background()
	cfg := newOPARegoConfig(nil)
	c, err := NewClient(ctx, cfg)
	if err != nil {
		t.Fatalf("NewClient err: %v", err)
	}
	return c
}

func TestReload_Success_IncrementsOK(t *testing.T) {
	c := newReloadableClient(t)
	before := testutil.ToFloat64(metricReloadTotal.WithLabelValues("ok"))

	if err := c.Reload(context.Background()); err != nil {
		t.Fatalf("Reload err: %v", err)
	}

	after := testutil.ToFloat64(metricReloadTotal.WithLabelValues("ok"))
	if after-before != 1 {
		t.Fatalf("reload_total{result=ok} delta want 1, got %v", after-before)
	}
}

func TestReload_FailurePreservesOldData(t *testing.T) {
	c := newReloadableClient(t)
	// 写一个哨兵到 opaData，便于断言"map 未被新建 map 替换"。
	c.opaData["__p9_test_sentinel__"] = "alive"
	oldLen := len(c.opaData)

	failBefore := testutil.ToFloat64(metricReloadTotal.WithLabelValues("fail"))

	// 让 DataProvider 返回非法 JSON 以触发 util.Unmarshal 报错 —— 这是 initOPARego
	// 会真正传出错误的路径（DataProvider 本身返回 err 会被框架吃掉并降级到 Data）。
	// 同时需要重点：非法内容必须让 nonCommentLineLength > 0，否则也会被降级为 defaultRBAC。
	c.config.OPARego.DataProvider = func(ctx context.Context) ([]byte, error) {
		return []byte(`[`), nil
	}

	err := c.Reload(context.Background())
	if err == nil {
		t.Fatalf("Reload expected to fail, got nil")
	}
	if !strings.Contains(err.Error(), "reload opa rego") {
		t.Fatalf("Reload err want wrap 'reload opa rego', got %v", err)
	}

	failAfter := testutil.ToFloat64(metricReloadTotal.WithLabelValues("fail"))
	if failAfter-failBefore != 1 {
		t.Fatalf("reload_total{result=fail} delta want 1, got %v", failAfter-failBefore)
	}

	// 关键断言：opaData 未被新建 map 替换。
	if v, ok := c.opaData["__p9_test_sentinel__"]; !ok || v != "alive" {
		t.Fatalf("opaData replaced despite Reload failure: %+v", c.opaData)
	}
	if len(c.opaData) != oldLen {
		t.Fatalf("opaData len changed: old=%d new=%d", oldLen, len(c.opaData))
	}
}

func TestReload_NilOPARego_IsNoop(t *testing.T) {
	c := &Client{
		config: &Config{PackageName: "x"},
	}
	before := testutil.ToFloat64(metricReloadTotal.WithLabelValues("ok"))
	if err := c.Reload(context.Background()); err != nil {
		t.Fatalf("Reload no-op should not error, got %v", err)
	}
	after := testutil.ToFloat64(metricReloadTotal.WithLabelValues("ok"))
	if after-before != 1 {
		t.Fatalf("reload_total{result=ok} delta want 1 (no-op still counts), got %v", after-before)
	}
}

func TestReload_DurationObserved(t *testing.T) {
	c := newReloadableClient(t)
	// CollectAndCount 返回 metric 系列数；Histogram 是 1 个系列（无 label）。
	// 调用 Observe 不增加系列数，但验证 collector 仍注册且 Gather 不 panic。
	before := testutil.CollectAndCount(metricLoaderDuration, "auth_policy_loader_duration_seconds")
	_ = c.Reload(context.Background())
	after := testutil.CollectAndCount(metricLoaderDuration, "auth_policy_loader_duration_seconds")
	if after < before {
		t.Fatalf("histogram series count decreased: before=%d after=%d", before, after)
	}
	if after == 0 {
		t.Fatalf("histogram not registered or not collected")
	}
}

func TestRegisterReloadHandler_POST_OK(t *testing.T) {
	c := newReloadableClient(t)
	mux := http.NewServeMux()
	c.RegisterReloadHandler(mux)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/admin/live/reload-policies", "application/json", nil)
	if err != nil {
		t.Fatalf("POST err: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status want 200, got %d", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("body[status] want ok, got %q", body["status"])
	}
}

func TestRegisterReloadHandler_GET_405(t *testing.T) {
	c := newReloadableClient(t)
	mux := http.NewServeMux()
	c.RegisterReloadHandler(mux)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/admin/live/reload-policies")
	if err != nil {
		t.Fatalf("GET err: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status want 405, got %d", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "error" {
		t.Fatalf("body[status] want error, got %q", body["status"])
	}
}

func TestRegisterReloadHandler_LoadFailure_500(t *testing.T) {
	c := newReloadableClient(t)
	c.config.OPARego.DataProvider = func(ctx context.Context) ([]byte, error) {
		return []byte(`[`), nil
	}

	mux := http.NewServeMux()
	c.RegisterReloadHandler(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/admin/live/reload-policies", "application/json", nil)
	if err != nil {
		t.Fatalf("POST err: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status want 500, got %d", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "error" {
		t.Fatalf("body[status] want error, got %q", body["status"])
	}
	if !strings.Contains(body["error"], "reload opa rego") {
		t.Fatalf("body[error] want wrap, got %q", body["error"])
	}
}

func TestReload_ConcurrentWithReaders_NoRace(t *testing.T) {
	c := newReloadableClient(t)

	// 1 个写 goroutine 反复 Reload；4 个读 goroutine 反复持 RLock 读 opaRego
	// + 调 mergeGrpcKitInput。仅断言全部退出且无 panic；真正的 data race 检测
	// 由 `go test -race` 在并发执行中捕获 —— 测试目的是把 Reload 与 Allow 等价
	// 读路径同时跑起来。
	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = c.Reload(context.Background())
			}
		}
	}()

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					// 模拟 Allow 的读路径：持 RLock 拷贝 query 引用。
					c.mu.RLock()
					_ = c.opaRego
					c.mu.RUnlock()

					input := map[string]interface{}{}
					c.mergeGrpcKitInput(context.Background(), input, nil)
				}
			}
		}()
	}

	for i := 0; i < 200; i++ {
		_ = c.Reload(context.Background())
	}
	close(stop)
	wg.Wait()
}

func TestMergeGrpcKitInput_MissIncrementsCounter(t *testing.T) {
	// P9 在 client.go 加的第二个改动：action_id 反查空时 Inc 计数。
	c := newReloadableClient(t)
	c.config.StaticDict = nil // 强制 ActionID = ""

	before := testutil.ToFloat64(metricActionLookupMiss)
	input := map[string]interface{}{}
	c.mergeGrpcKitInput(context.Background(), input, nil)
	after := testutil.ToFloat64(metricActionLookupMiss)

	if after-before != 1 {
		t.Fatalf("action_lookup_miss delta want 1, got %v", after-before)
	}

	// grpc_kit.action_id 应为空字符串占位（Rego 兼容）。
	gk, ok := input["grpc_kit"].(map[string]any)
	if !ok {
		t.Fatalf("input[grpc_kit] missing or wrong type: %+v", input["grpc_kit"])
	}
	if gk["action_id"] != "" {
		t.Fatalf("action_id want empty, got %v", gk["action_id"])
	}
}
