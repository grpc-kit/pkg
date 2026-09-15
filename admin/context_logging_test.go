package admin

import (
	"context"
	"log/slog"
	"testing"
)

type contextCaptureHandler struct {
	contexts chan context.Context
}

func (h *contextCaptureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *contextCaptureHandler) Handle(ctx context.Context, _ slog.Record) error {
	h.contexts <- ctx
	return nil
}

func (h *contextCaptureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *contextCaptureHandler) WithGroup(string) slog.Handler      { return h }

func TestAdminHelpersPropagateContextToLogs(t *testing.T) {
	type contextKey struct{}

	tests := []struct {
		name string
		call func(context.Context, *slog.Logger)
	}{
		{
			name: "global setting audit",
			call: func(ctx context.Context, logger *slog.Logger) {
				(&KnownAdminAPI{logger: logger}).auditGlobalSettingMutation(ctx, "update", "security", "key", 1, "success")
			},
		},
		{
			name: "verified identifier warning",
			call: func(ctx context.Context, logger *slog.Logger) {
				(&socialUsers{logger: logger, ProviderName: "oidc"}).canonicalVerifiedIdentifierHashes(ctx, verifiedIdentityClaims{
					Email:         "invalid",
					EmailVerified: true,
				})
			},
		},
		{
			name: "wechat request error",
			call: func(ctx context.Context, logger *slog.Logger) {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				_, _ = newWechatOpen(logger, "appid", "secret").code2Session(canceled, "https://example.invalid/session", "code")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contexts := make(chan context.Context, 1)
			logger := slog.New(&contextCaptureHandler{contexts: contexts})
			ctx := context.WithValue(t.Context(), contextKey{}, tt.name)

			tt.call(ctx, logger)

			loggedContext := <-contexts
			if got := loggedContext.Value(contextKey{}); got != tt.name {
				t.Fatalf("logged context value = %v, want %q", got, tt.name)
			}
		})
	}
}
