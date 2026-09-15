package sd

import (
	"context"
	"log/slog"
)

const (
	eventRegistrationRetry          = "sd_registration_retry"
	eventResolverLookupFailed       = "sd_resolver_lookup_failed"
	eventResolverStateRestoreFailed = "sd_resolver_state_restore_failed"
	eventResolverStateUpdateFailed  = "sd_resolver_state_update_failed"
	eventRegistrationSucceeded      = "sd_registration_succeeded"
	eventKeepaliveReceived          = "sd_keepalive_received"
	eventResolverStateUpdated       = "sd_resolver_state_updated"
)

func logRegistrationRetry(ctx context.Context, logger *slog.Logger, err error) {
	logger.LogAttrs(ctx, slog.LevelError, "service registration failed; retrying",
		slog.String("event", eventRegistrationRetry),
		slog.Any("error", err),
	)
}

func logResolverLookupFailed(ctx context.Context, logger *slog.Logger, err error) {
	logger.LogAttrs(ctx, slog.LevelError, "failed to resolve service; using last known addresses",
		slog.String("event", eventResolverLookupFailed),
		slog.Any("error", err),
	)
}

func logResolverStateRestoreFailed(ctx context.Context, logger *slog.Logger, err error) {
	logger.LogAttrs(ctx, slog.LevelError, "failed to restore last resolver state",
		slog.String("event", eventResolverStateRestoreFailed),
		slog.Any("error", err),
	)
}

func logResolverStateUpdateFailed(ctx context.Context, logger *slog.Logger, addressCount int, err error) {
	logger.LogAttrs(ctx, slog.LevelError, "failed to update resolver state",
		slog.String("event", eventResolverStateUpdateFailed),
		slog.Int("address_count", addressCount),
		slog.Any("error", err),
	)
}

func logRegistrationSucceeded(ctx context.Context, logger *slog.Logger, ttl, leaseID int64) {
	logger.LogAttrs(ctx, slog.LevelDebug, "registered service endpoint",
		slog.String("event", eventRegistrationSucceeded),
		slog.Int64("ttl_seconds", ttl),
		slog.Int64("lease_id", leaseID),
	)
}

func logKeepaliveReceived(ctx context.Context, logger *slog.Logger, ttl, leaseID int64) {
	logger.LogAttrs(ctx, slog.LevelDebug, "received service lease keepalive",
		slog.String("event", eventKeepaliveReceived),
		slog.Int64("ttl_seconds", ttl),
		slog.Int64("lease_id", leaseID),
	)
}

func logResolverStateUpdated(ctx context.Context, logger *slog.Logger, addressCount int) {
	logger.LogAttrs(ctx, slog.LevelDebug, "updated resolver state",
		slog.String("event", eventResolverStateUpdated),
		slog.Int("address_count", addressCount),
	)
}
