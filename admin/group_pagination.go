package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/grpc-kit/pkg/errs"
)

// Group list cursors encode only an integer ID. Consequently, cursor mode is
// intentionally restricted to a deterministic ID order; offset mode retains
// the API's configurable presentation orders.
func requireIDCursorOrder(ctx context.Context, orderBy string) error {
	if strings.TrimSpace(orderBy) == "" {
		return nil
	}
	return errs.InvalidArgument(ctx).WithMessage("order_by is not supported with page_token pagination")
}

func decodeGroupIDPageToken(ctx context.Context, token string) (int, error) {
	if token == "" {
		return 0, nil
	}
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return 0, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid page_token: %v", err))
	}
	var lastID int
	if err := json.Unmarshal(data, &lastID); err != nil {
		return 0, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid page_token format: %v", err))
	}
	if lastID <= 0 {
		return 0, errs.InvalidArgument(ctx).WithMessage("invalid page_token: id must be positive")
	}
	return lastID, nil
}

func encodeGroupIDPageToken(lastID int) string {
	if lastID <= 0 {
		return ""
	}
	data, err := json.Marshal(lastID)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)
}
