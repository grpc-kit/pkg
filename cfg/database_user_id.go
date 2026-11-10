package cfg

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/lib/pq"
)

// Calibration must finish before a database-backed admin server is registered.
// The deadline also bounds waits on locks held by other instances.
func (c *LocalConfig) ensureLionUsersIDStart(ctx context.Context, db *sql.DB) error {
	if err := c.Security.validateStaticUserIDs(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	switch c.Database.Driver {
	case DatabaseDriverPostgresql:
		return c.ensurePostgresUserIDs(ctx, db)
	case DatabaseDriverMysql:
		return c.ensureMySQLUserIDs(ctx, db)
	default:
		return ErrDatabaseNotSupportDriver
	}
}

type userIDQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Existing low IDs remain unchanged, but must not alias configured static users.
func (c *LocalConfig) checkStaticDatabaseUserIDs(ctx context.Context, db userIDQuerier) error {
	if c.Security == nil || c.Security.Authentication == nil {
		return nil
	}
	placeholder := "?"
	if c.Database.Driver == DatabaseDriverPostgresql {
		placeholder = "$1"
	}
	for _, user := range c.Security.Authentication.HTTPUsers {
		id, err := crypto.ResolveStaticUserID(user.Username, user.UserID)
		if err != nil {
			return err
		}
		var exists bool
		query := "SELECT EXISTS (SELECT 1 FROM lion_users WHERE id = " + placeholder + ")"
		if err := db.QueryRowContext(ctx, query, id).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("database user_id %d conflicts with a configured static user; migrate the legacy identity before enabling admin", id)
		}
	}
	return nil
}

func requiredLionUserID(ctx context.Context, db userIDQuerier) (int64, error) {
	var highest int64
	if err := db.QueryRowContext(ctx, "SELECT COALESCE(MAX(id), 0) FROM lion_users").Scan(&highest); err != nil {
		return 0, err
	}
	if highest == math.MaxInt64 {
		return 0, fmt.Errorf("lion user ID space exhausted")
	}
	return max(int64(lionUsersIDStart), highest+1), nil
}

func (c *LocalConfig) ensurePostgresUserIDs(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// INSERT acquires its table lock before requesting a sequence value. Taking
	// locks in the same order excludes both writers and other calibrators.
	if _, err := tx.ExecContext(ctx, "LOCK TABLE lion_users IN ACCESS EXCLUSIVE MODE"); err != nil {
		return err
	}
	var namespace, name string
	var increment int64
	if err := tx.QueryRowContext(ctx, `SELECT n.nspname, s.relname, p.seqincrement
FROM pg_class s JOIN pg_namespace n ON n.oid = s.relnamespace
JOIN pg_sequence p ON p.seqrelid = s.oid
WHERE s.oid = pg_get_serial_sequence('lion_users', 'id')::regclass`).Scan(&namespace, &name, &increment); err != nil {
		return fmt.Errorf("resolve lion_users identity sequence: %w", err)
	}
	if increment != 1 {
		return fmt.Errorf("lion_users identity sequence must increment by 1")
	}
	sequence := pq.QuoteIdentifier(namespace) + "." + pq.QuoteIdentifier(name)
	// This transactional ALTER locks the sequence against direct nextval calls
	// and invalidates preallocated session caches, without resetting its value.
	if _, err := tx.ExecContext(ctx, "ALTER SEQUENCE "+sequence+" NO CYCLE"); err != nil {
		return err
	}
	var last int64
	var called bool
	if err := tx.QueryRowContext(ctx, "SELECT last_value, is_called FROM "+sequence).Scan(&last, &called); err != nil {
		return err
	}
	next := last
	if called {
		if last == math.MaxInt64 {
			return fmt.Errorf("lion user ID space exhausted")
		}
		next++
	}
	required, err := requiredLionUserID(ctx, tx)
	if err != nil {
		return err
	}
	if next < required {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("ALTER SEQUENCE %s RESTART WITH %d", sequence, required)); err != nil {
			return err
		}
	}
	if err := c.checkStaticDatabaseUserIDs(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (c *LocalConfig) ensureMySQLUserIDs(ctx context.Context, db *sql.DB) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	// LOCK TABLES and session settings belong to a physical connection. Always
	// discard it, including on cancellation, so neither can leak into the pool.
	defer func() {
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		_ = conn.Close()
	}()
	if _, err := conn.ExecContext(ctx, "LOCK TABLES lion_users WRITE"); err != nil {
		return err
	}
	// MySQL 8 caches INFORMATION_SCHEMA statistics by default. MySQL 5.7 has
	// no such cache or variable (1193); its live counter can be queried directly.
	if _, err := conn.ExecContext(ctx, "SET SESSION information_schema_stats_expiry = 0"); err != nil {
		var serverError *mysql.MySQLError
		if !errors.As(err, &serverError) || serverError.Number != 1193 {
			return err
		}
	}
	var next sql.NullInt64
	if err := conn.QueryRowContext(ctx, `SELECT AUTO_INCREMENT FROM information_schema.TABLES
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'lion_users'`).Scan(&next); err != nil {
		return err
	}
	if !next.Valid {
		return fmt.Errorf("lion_users must have an AUTO_INCREMENT identity")
	}
	required, err := requiredLionUserID(ctx, conn)
	if err != nil {
		return err
	}
	if err := c.checkStaticDatabaseUserIDs(ctx, conn); err != nil {
		return err
	}
	if next.Int64 < required {
		_, err = conn.ExecContext(ctx, fmt.Sprintf("ALTER TABLE lion_users AUTO_INCREMENT = %d", required))
		return err
	}
	return nil
}
