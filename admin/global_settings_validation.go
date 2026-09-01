package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/grpc-kit/pkg/errs"
)

const (
	maxGlobalSettingKeyBytes         = 128
	maxGlobalSettingDescriptionRunes = 255
	maxGlobalSettingValueBytes       = 64 * 1024
	maxGlobalSettingStringArrayItems = 256
	maxGlobalSettingJSONDepth        = 64
)

var globalSettingKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)

func validateGlobalSettingKey(ctx context.Context, settingKey string) error {
	if err := validateGlobalSettingKeyFormat(ctx, settingKey); err != nil {
		return err
	}
	if looksLikeSecretGlobalSettingKey(settingKey) {
		return errs.InvalidArgument(ctx).WithMessage("secret-like configuration keys are not allowed in global settings")
	}
	return nil
}

func validateGlobalSettingKeyFormat(ctx context.Context, settingKey string) error {
	if settingKey == "" {
		return errs.InvalidArgument(ctx).WithMessage("setting_key is required")
	}
	if len(settingKey) > maxGlobalSettingKeyBytes || !globalSettingKeyPattern.MatchString(settingKey) {
		return errs.InvalidArgument(ctx).WithMessage("setting_key must use lowercase letters, digits, dots, underscores, or hyphens and be at most 128 bytes")
	}
	return nil
}

func looksLikeSecretGlobalSettingKey(settingKey string) bool {
	segments := strings.FieldsFunc(strings.ToLower(settingKey), func(r rune) bool {
		return r == '.' || r == '_' || r == '-'
	})
	for i, segment := range segments {
		switch segment {
		case "password", "passwd", "secret", "credential", "credentials", "privatekey", "apikey", "accesskey":
			return true
		case "token":
			if i == len(segments)-1 {
				return true
			}
		}
		if i+1 >= len(segments) {
			continue
		}
		pair := segment + "." + segments[i+1]
		switch pair {
		case "api.key", "access.key", "secret.key", "private.key", "client.secret", "bearer.token", "session.token", "refresh.token", "access.token":
			return true
		}
	}
	return false
}

func validateGlobalSettingDescription(ctx context.Context, description string) error {
	if utf8.RuneCountInString(description) > maxGlobalSettingDescriptionRunes {
		return errs.InvalidArgument(ctx).WithMessage("description must be at most 255 characters")
	}
	return nil
}

func normalizeGlobalSettingValue(ctx context.Context, settingKey, value string, spec globalSettingSpec) (string, error) {
	if len(value) > maxGlobalSettingValueBytes {
		return "", errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("%s value must be at most 64 KiB", settingKey))
	}

	if spec.ValueType == globalSettingValueTypeString {
		if spec.MaxLen > 0 && utf8.RuneCountInString(value) > spec.MaxLen {
			return "", errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("%s length must be <= %d", settingKey, spec.MaxLen))
		}
		return value, nil
	}

	value = strings.TrimSpace(value)
	switch spec.ValueType {
	case globalSettingValueTypeBool:
		if value != "true" && value != "false" {
			return "", invalidGlobalSettingValue(ctx, settingKey, spec.ValueType)
		}
		return value, nil
	case globalSettingValueTypeInt:
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return "", invalidGlobalSettingValue(ctx, settingKey, spec.ValueType)
		}
		if spec.MinInt != nil && parsed < int64(*spec.MinInt) {
			return "", errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("%s must be >= %d", settingKey, *spec.MinInt))
		}
		if spec.MaxInt != nil && parsed > int64(*spec.MaxInt) {
			return "", errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("%s must be <= %d", settingKey, *spec.MaxInt))
		}
		return strconv.FormatInt(parsed, 10), nil
	case globalSettingValueTypeFloat:
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil || math.IsInf(parsed, 0) || math.IsNaN(parsed) {
			return "", invalidGlobalSettingValue(ctx, settingKey, spec.ValueType)
		}
		return strconv.FormatFloat(parsed, 'g', -1, 64), nil
	case globalSettingValueTypeDuration:
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return "", invalidGlobalSettingValue(ctx, settingKey, spec.ValueType)
		}
		if spec.MinDuration != nil && parsed < *spec.MinDuration {
			return "", errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("%s must be >= %s", settingKey, spec.MinDuration.String()))
		}
		if spec.MaxDuration != nil && parsed > *spec.MaxDuration {
			return "", errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("%s must be <= %s", settingKey, spec.MaxDuration.String()))
		}
		return parsed.String(), nil
	case globalSettingValueTypeStringArray:
		var items []string
		if err := decodeSingleJSON([]byte(value), &items); err != nil || items == nil {
			return "", invalidGlobalSettingValue(ctx, settingKey, spec.ValueType)
		}
		if len(items) > maxGlobalSettingStringArrayItems {
			return "", errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("%s must contain at most %d items", settingKey, maxGlobalSettingStringArrayItems))
		}
		encoded, err := json.Marshal(items)
		if err != nil {
			return "", invalidGlobalSettingValue(ctx, settingKey, spec.ValueType)
		}
		return string(encoded), nil
	case globalSettingValueTypeJSON:
		var decoded any
		if err := decodeSingleJSON([]byte(value), &decoded); err != nil {
			return "", invalidGlobalSettingValue(ctx, settingKey, spec.ValueType)
		}
		if globalSettingJSONDepth(decoded) > maxGlobalSettingJSONDepth {
			return "", errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("%s JSON nesting must be at most %d levels", settingKey, maxGlobalSettingJSONDepth))
		}
		encoded, err := json.Marshal(decoded)
		if err != nil {
			return "", invalidGlobalSettingValue(ctx, settingKey, spec.ValueType)
		}
		return string(encoded), nil
	default:
		return "", errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("unsupported value_type for %s", settingKey))
	}
}

// validateGlobalSettingValue is kept as the validation-only entry point used by
// focused registry tests. Write paths use normalizeGlobalSettingValue directly.
func validateGlobalSettingValue(settingKey, value string, spec globalSettingSpec) error {
	_, err := normalizeGlobalSettingValue(context.Background(), settingKey, value, spec)
	return err
}

func invalidGlobalSettingValue(ctx context.Context, settingKey string, valueType globalSettingValueType) error {
	return errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid %s value for %s", valueType, settingKey))
}

func decodeSingleJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("unexpected trailing JSON content")
	}
	return nil
}

func globalSettingJSONDepth(value any) int {
	switch typed := value.(type) {
	case []any:
		maxDepth := 1
		for _, item := range typed {
			maxDepth = max(maxDepth, 1+globalSettingJSONDepth(item))
		}
		return maxDepth
	case map[string]any:
		maxDepth := 1
		for _, item := range typed {
			maxDepth = max(maxDepth, 1+globalSettingJSONDepth(item))
		}
		return maxDepth
	default:
		return 0
	}
}
