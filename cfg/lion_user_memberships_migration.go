package cfg

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
)

const (
	legacyMembershipTargetGroup      = 1
	legacyMembershipTargetDepartment = 2
	legacyMembershipPrimary          = 1
)

func backfillLegacyLionUserMemberships(ctx context.Context, db *sql.DB, driver string) error {
	if err := backfillLegacyGroupMembers(ctx, db, driver); err != nil {
		return err
	}
	if err := backfillLegacyDepartmentMembers(ctx, db, driver); err != nil {
		return err
	}
	return nil
}

func backfillLegacyGroupMembers(ctx context.Context, db *sql.DB, driver string) error {
	rows, err := db.QueryContext(ctx, `
		SELECT user_id, group_id, member_role, member_status, joined_at, expired_at, metadata, description, created_by, updated_by, created_at, updated_at
		FROM lion_group_members
	`)
	if err != nil {
		if isMissingLegacyTableError(err) {
			return nil
		}
		return err
	}
	defer rows.Close()

	upsert := legacyMembershipUpsertStatement(driver)
	for rows.Next() {
		var userID int
		var groupID int
		var memberRole int
		var memberStatus int
		var joinedAt sql.NullTime
		var expiredAt sql.NullTime
		var metadata []byte
		var description sql.NullString
		var createdBy sql.NullInt64
		var updatedBy sql.NullInt64
		var createdAt sql.NullTime
		var updatedAt sql.NullTime

		if err := rows.Scan(
			&userID,
			&groupID,
			&memberRole,
			&memberStatus,
			&joinedAt,
			&expiredAt,
			&metadata,
			&description,
			&createdBy,
			&updatedBy,
			&createdAt,
			&updatedAt,
		); err != nil {
			return err
		}

		metadataJSON, err := normalizeLegacyJSONMetadata(metadata)
		if err != nil {
			return err
		}

		if _, err := db.ExecContext(ctx, upsert,
			userID,
			legacyMembershipTargetGroup,
			groupID,
			memberRole,
			memberStatus,
			0,
			nullableTimeValue(joinedAt),
			nullableTimeValue(expiredAt),
			metadataJSON,
			nullableStringValue(description),
			nullableInt64Value(createdBy),
			nullableInt64Value(updatedBy),
			nullableTimeValue(createdAt),
			nullableTimeValue(updatedAt),
		); err != nil {
			return err
		}
	}

	return rows.Err()
}

func backfillLegacyDepartmentMembers(ctx context.Context, db *sql.DB, driver string) error {
	rows, err := db.QueryContext(ctx, `
		SELECT user_id, department_id, member_role, member_status, member_type, expired_at, metadata, description, created_by, updated_by, created_at, updated_at
		FROM lion_department_members
	`)
	if err != nil {
		if isMissingLegacyTableError(err) {
			return nil
		}
		return err
	}
	defer rows.Close()

	upsert := legacyMembershipUpsertStatement(driver)
	for rows.Next() {
		var userID int
		var departmentID int
		var memberRole int
		var memberStatus int
		var memberType sql.NullInt64
		var expiredAt sql.NullTime
		var metadata sql.NullString
		var description sql.NullString
		var createdBy sql.NullInt64
		var updatedBy sql.NullInt64
		var createdAt sql.NullTime
		var updatedAt sql.NullTime

		if err := rows.Scan(
			&userID,
			&departmentID,
			&memberRole,
			&memberStatus,
			&memberType,
			&expiredAt,
			&metadata,
			&description,
			&createdBy,
			&updatedBy,
			&createdAt,
			&updatedAt,
		); err != nil {
			return err
		}

		metadataJSON, err := normalizeLegacyStringMetadata(metadata)
		if err != nil {
			return err
		}

		memberTypeValue := legacyMembershipPrimary
		if memberType.Valid {
			memberTypeValue = int(memberType.Int64)
		}

		joinedAt := createdAt
		if _, err := db.ExecContext(ctx, upsert,
			userID,
			legacyMembershipTargetDepartment,
			departmentID,
			memberRole,
			memberStatus,
			memberTypeValue,
			nullableTimeValue(joinedAt),
			nullableTimeValue(expiredAt),
			metadataJSON,
			nullableStringValue(description),
			nullableInt64Value(createdBy),
			nullableInt64Value(updatedBy),
			nullableTimeValue(createdAt),
			nullableTimeValue(updatedAt),
		); err != nil {
			return err
		}
	}

	return rows.Err()
}

func legacyMembershipUpsertStatement(driver string) string {
	if driver == DatabaseDriverPostgresql {
		return `
			INSERT INTO lion_user_memberships (
				user_id, target_type, target_id, member_role, member_status, member_type,
				joined_at, expired_at, metadata, description, created_by, updated_by, created_at, updated_at
			) VALUES (
				$1, $2, $3, $4, $5, $6,
				$7, $8, $9, $10, $11, $12, $13, $14
			)
			ON CONFLICT (user_id, target_type, target_id) DO UPDATE SET
				member_role = EXCLUDED.member_role,
				member_status = EXCLUDED.member_status,
				member_type = EXCLUDED.member_type,
				joined_at = EXCLUDED.joined_at,
				expired_at = EXCLUDED.expired_at,
				metadata = EXCLUDED.metadata,
				description = EXCLUDED.description,
				created_by = EXCLUDED.created_by,
				updated_by = EXCLUDED.updated_by,
				created_at = EXCLUDED.created_at,
				updated_at = EXCLUDED.updated_at
		`
	}

	return `
		INSERT INTO lion_user_memberships (
			user_id, target_type, target_id, member_role, member_status, member_type,
			joined_at, expired_at, metadata, description, created_by, updated_by, created_at, updated_at
		) VALUES (
			?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?, ?
		)
		ON DUPLICATE KEY UPDATE
			member_role = VALUES(member_role),
			member_status = VALUES(member_status),
			member_type = VALUES(member_type),
			joined_at = VALUES(joined_at),
			expired_at = VALUES(expired_at),
			metadata = VALUES(metadata),
			description = VALUES(description),
			created_by = VALUES(created_by),
			updated_by = VALUES(updated_by),
			created_at = VALUES(created_at),
			updated_at = VALUES(updated_at)
	`
}

func isMissingLegacyTableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "doesn't exist") ||
		strings.Contains(message, "does not exist") ||
		strings.Contains(message, "unknown table") ||
		strings.Contains(message, "no such table")
}

func normalizeLegacyJSONMetadata(raw []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}
	if json.Valid([]byte(trimmed)) {
		return []byte(trimmed), nil
	}
	return json.Marshal(map[string]string{"raw": trimmed})
}

func normalizeLegacyStringMetadata(raw sql.NullString) ([]byte, error) {
	if !raw.Valid {
		return nil, nil
	}
	trimmed := strings.TrimSpace(raw.String)
	if trimmed == "" {
		return nil, nil
	}
	if json.Valid([]byte(trimmed)) {
		return []byte(trimmed), nil
	}
	return json.Marshal(map[string]string{"raw": trimmed})
}

func nullableStringValue(value sql.NullString) any {
	if value.Valid {
		return value.String
	}
	return nil
}

func nullableInt64Value(value sql.NullInt64) any {
	if value.Valid {
		return value.Int64
	}
	return nil
}

func nullableTimeValue(value sql.NullTime) any {
	if value.Valid {
		return value.Time
	}
	return nil
}
