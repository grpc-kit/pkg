package admin

import (
	"context"
	"strings"

	"github.com/grpc-kit/pkg/errs"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func requiredGroupUpdatePaths(ctx context.Context, mask *fieldmaskpb.FieldMask) ([]string, error) {
	if mask == nil || len(mask.Paths) == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("update_mask is required")
	}
	paths := make([]string, 0, len(mask.Paths))
	seen := make(map[string]struct{}, len(mask.Paths))
	for _, rawPath := range mask.Paths {
		path := strings.TrimSpace(rawPath)
		if path == "" {
			return nil, errs.InvalidArgument(ctx).WithMessage("update_mask contains an empty path")
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	return paths, nil
}
