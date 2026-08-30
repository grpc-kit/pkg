package admin

import (
	"container/list"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/predicate"
	"github.com/grpc-kit/pkg/lion/users"
)

const (
	maxUserFilterBytes      = 4096
	maxUserFilterConditions = 16
	userFilterCacheEntries  = 256
	userFilterCacheBytes    = userFilterCacheEntries * maxUserFilterBytes
)

type userFilterOperator uint8

const (
	userFilterEqual userFilterOperator = iota + 1
	userFilterNotEqual
)

type userFilterCondition struct {
	field     string
	op        userFilterOperator
	enumValue int
	boolValue bool
}

type compiledUserFilter struct {
	canonical  string
	conditions []userFilterCondition
}

func (f *compiledUserFilter) predicates() []predicate.Users {
	out := make([]predicate.Users, 0, len(f.conditions)+1)
	for _, condition := range f.conditions {
		switch condition.field {
		case "type":
			if condition.op == userFilterEqual {
				out = append(out, users.UserTypeEQ(condition.enumValue))
			} else {
				out = append(out, users.UserTypeNEQ(condition.enumValue))
			}
		case "status":
			if condition.op == userFilterEqual {
				out = append(out, users.UserStatusEQ(condition.enumValue))
			} else {
				out = append(out, users.UserStatusNEQ(condition.enumValue))
			}
		case "email_verified":
			value := condition.boolValue
			if condition.op == userFilterNotEqual {
				value = !value
			}
			out = append(out, users.EmailVerifiedEQ(value))
		case "phone_number_verified":
			value := condition.boolValue
			if condition.op == userFilterNotEqual {
				value = !value
			}
			out = append(out, users.PhoneNumberVerifiedEQ(value))
		}
	}
	return append(out, users.DeletedAtIsNil())
}

func (f *compiledUserFilter) matches(user *lion.Users) bool {
	if user == nil || user.DeletedAt != nil {
		return false
	}
	for _, condition := range f.conditions {
		matched := false
		switch condition.field {
		case "type":
			matched = user.UserType == condition.enumValue
		case "status":
			matched = user.UserStatus == condition.enumValue
		case "email_verified":
			matched = user.EmailVerified == condition.boolValue
		case "phone_number_verified":
			matched = user.PhoneNumberVerified == condition.boolValue
		}
		if condition.op == userFilterNotEqual {
			matched = !matched
		}
		if !matched {
			return false
		}
	}
	return true
}

type userFilterTokenKind uint8

const (
	userFilterEOF userFilterTokenKind = iota
	userFilterIdentifier
	userFilterEQ
	userFilterNEQ
)

type userFilterToken struct {
	kind  userFilterTokenKind
	value string
}

type userFilterLexer struct {
	input string
	pos   int
}

func (l *userFilterLexer) next() (userFilterToken, error) {
	for l.pos < len(l.input) {
		r, size := utf8.DecodeRuneInString(l.input[l.pos:])
		if !unicode.IsSpace(r) {
			break
		}
		l.pos += size
	}
	if l.pos == len(l.input) {
		return userFilterToken{kind: userFilterEOF}, nil
	}
	if strings.HasPrefix(l.input[l.pos:], "!=") {
		l.pos += 2
		return userFilterToken{kind: userFilterNEQ, value: "!="}, nil
	}
	if l.input[l.pos] == '=' {
		l.pos++
		return userFilterToken{kind: userFilterEQ, value: "="}, nil
	}
	start := l.pos
	for l.pos < len(l.input) {
		r, size := utf8.DecodeRuneInString(l.input[l.pos:])
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_') {
			break
		}
		l.pos += size
	}
	if start == l.pos {
		return userFilterToken{}, fmt.Errorf("unexpected token at byte %d", l.pos)
	}
	return userFilterToken{kind: userFilterIdentifier, value: l.input[start:l.pos]}, nil
}

func parseAndValidateUserFilter(input string) (*compiledUserFilter, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("user_filter is empty")
	}
	if len(input) > maxUserFilterBytes {
		return nil, fmt.Errorf("user_filter exceeds %d bytes", maxUserFilterBytes)
	}
	lexer := &userFilterLexer{input: input}
	conditions := make([]userFilterCondition, 0, 4)
	canonical := make([]string, 0, 4)
	afterAnd := false
	for {
		fieldToken, err := lexer.next()
		if err != nil {
			return nil, err
		}
		if fieldToken.kind == userFilterEOF {
			if len(conditions) == 0 {
				return nil, fmt.Errorf("user_filter is empty")
			}
			if afterAnd {
				return nil, fmt.Errorf("condition %d: expected field after AND", len(conditions)+1)
			}
			break
		}
		afterAnd = false
		if fieldToken.kind != userFilterIdentifier {
			return nil, fmt.Errorf("condition %d: expected field", len(conditions)+1)
		}
		fieldName := strings.ToLower(fieldToken.value)
		operatorToken, err := lexer.next()
		if err != nil {
			return nil, err
		}
		var operator userFilterOperator
		switch operatorToken.kind {
		case userFilterEQ:
			operator = userFilterEqual
		case userFilterNEQ:
			operator = userFilterNotEqual
		default:
			return nil, fmt.Errorf("condition %d field %q: expected = or !=", len(conditions)+1, fieldName)
		}
		valueToken, err := lexer.next()
		if err != nil {
			return nil, err
		}
		if valueToken.kind != userFilterIdentifier {
			return nil, fmt.Errorf("condition %d field %q: expected enum or boolean value", len(conditions)+1, fieldName)
		}
		condition := userFilterCondition{field: fieldName, op: operator}
		canonicalValue, err := validateUserFilterValue(&condition, valueToken.value)
		if err != nil {
			return nil, fmt.Errorf("condition %d field %q: %w", len(conditions)+1, fieldName, err)
		}
		conditions = append(conditions, condition)
		canonical = append(canonical, fmt.Sprintf("%s %s %s", fieldName, operatorToken.value, canonicalValue))
		if len(conditions) > maxUserFilterConditions {
			return nil, fmt.Errorf("user_filter exceeds %d conditions", maxUserFilterConditions)
		}

		next, err := lexer.next()
		if err != nil {
			return nil, err
		}
		if next.kind == userFilterEOF {
			break
		}
		if next.kind != userFilterIdentifier || !strings.EqualFold(next.value, "AND") {
			return nil, fmt.Errorf("condition %d: expected AND or end of expression", len(conditions))
		}
		afterAnd = true
	}
	return &compiledUserFilter{canonical: strings.Join(canonical, " AND "), conditions: conditions}, nil
}

func validateUserFilterValue(condition *userFilterCondition, raw string) (string, error) {
	upper := strings.ToUpper(raw)
	switch condition.field {
	case "type":
		value, ok := adminv1.User_Type_value[upper]
		if !ok || value == int32(adminv1.User_TYPE_UNSPECIFIED) {
			// 错误信息只含字段与类别，不回显原始值（§4.1.4）。
			return "", fmt.Errorf("value is not an allowed User.Type name")
		}
		condition.enumValue = int(value)
		return adminv1.User_Type(value).String(), nil
	case "status":
		value, ok := adminv1.User_Status_value[upper]
		if !ok || value == int32(adminv1.User_STATUS_UNSPECIFIED) {
			// 同上：不回显原始值（§4.1.4）。
			return "", fmt.Errorf("value is not an allowed User.Status name")
		}
		condition.enumValue = int(value)
		return adminv1.User_Status(value).String(), nil
	case "email_verified", "phone_number_verified":
		switch strings.ToLower(raw) {
		case "true":
			condition.boolValue = true
			return "true", nil
		case "false":
			return "false", nil
		default:
			return "", fmt.Errorf("expected true or false")
		}
	default:
		return "", fmt.Errorf("field is not allowed")
	}
}

type userFilterCacheEntry struct {
	key    [sha256.Size]byte
	filter *compiledUserFilter
	bytes  int
}

type userFilterLRU struct {
	mu      sync.Mutex
	items   map[[sha256.Size]byte]*list.Element
	order   *list.List
	maxSize int
	bytes   int
}

var compiledUserFilters = userFilterLRU{
	items:   make(map[[sha256.Size]byte]*list.Element),
	order:   list.New(),
	maxSize: userFilterCacheBytes,
}

func compileUserFilter(input string) (*compiledUserFilter, error) {
	// Stored rules are canonical. Check them before parsing so repeated login
	// and authorization evaluations take the true cache-hit path.
	inputKey := sha256.Sum256([]byte(input))
	compiledUserFilters.mu.Lock()
	if element, ok := compiledUserFilters.items[inputKey]; ok {
		entry := element.Value.(*userFilterCacheEntry)
		if entry.filter.canonical == input {
			compiledUserFilters.order.MoveToFront(element)
			compiledUserFilters.mu.Unlock()
			return entry.filter, nil
		}
	}
	compiledUserFilters.mu.Unlock()

	parsed, err := parseAndValidateUserFilter(input)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256([]byte(parsed.canonical))
	compiledUserFilters.mu.Lock()
	defer compiledUserFilters.mu.Unlock()
	if element, ok := compiledUserFilters.items[key]; ok {
		entry := element.Value.(*userFilterCacheEntry)
		if entry.filter.canonical == parsed.canonical {
			compiledUserFilters.order.MoveToFront(element)
			return entry.filter, nil
		}
		// A SHA-256 collision must never replace or alias the existing rule.
		return parsed, nil
	}
	entry := &userFilterCacheEntry{key: key, filter: parsed, bytes: len(parsed.canonical)}
	element := compiledUserFilters.order.PushFront(entry)
	compiledUserFilters.items[key] = element
	compiledUserFilters.bytes += entry.bytes
	for compiledUserFilters.order.Len() > userFilterCacheEntries || compiledUserFilters.bytes > compiledUserFilters.maxSize {
		oldest := compiledUserFilters.order.Back()
		oldEntry := oldest.Value.(*userFilterCacheEntry)
		delete(compiledUserFilters.items, oldEntry.key)
		compiledUserFilters.bytes -= oldEntry.bytes
		compiledUserFilters.order.Remove(oldest)
	}
	return parsed, nil
}
