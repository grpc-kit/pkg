package cfg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/grpc-kit/pkg/lion"
	pklogging "github.com/grpc-kit/pkg/logging"
	_ "github.com/lib/pq"
)

var legacyLionAuthzTables = []string{
	"lion_role_permissions",
	"lion_permission_bindings",
	"lion_resource_scopes",
	"lion_permissions",
	"lion_scopes",
}

var (
	ErrDatabaseNotInit          = errors.New("database not initialize")
	ErrDatabaseNotEnable        = errors.New("database not enable")
	ErrDatabaseNotSupportDriver = errors.New("database driver not support")
	ErrDatabaseParamsMust       = errors.New("database dbname username or password must")
)

const (
	DatabaseDriverMysql      = "mysql"
	DatabaseDriverPostgresql = "postgres"
)

// lionUsersIDStart lion_users 表自增起点（见 adm 仓库 docs/spec/user-id.md）：
// 与静态用户 Username2UserID 折算值域 [100000, 109999] 永久不相交。
const lionUsersIDStart = 123456

// lionUsersIDStartStmt 返回将 lion_users 自增起点推到 lionUsersIDStart 的方言语句。
// 两类语句均幂等：postgres 仅在当前序列落后时前推（GREATEST 不回退已有值）；
// mysql 的 AUTO_INCREMENT 会被服务端钳制到 max(id)+1，不会下调。
func lionUsersIDStartStmt(driver string) (string, error) {
	switch driver {
	case DatabaseDriverPostgresql:
		// setval(seq, 123455, true)：下一次 nextval 即为 123456
		return fmt.Sprintf(
			"SELECT setval('lion_users_id_seq', GREATEST(("+
				"SELECT last_value FROM lion_users_id_seq), %d), true)",
			lionUsersIDStart-1,
		), nil
	case DatabaseDriverMysql:
		return fmt.Sprintf("ALTER TABLE lion_users AUTO_INCREMENT = %d", lionUsersIDStart), nil
	default:
		return "", ErrDatabaseNotSupportDriver
	}
}

// ensureLionUsersIDStart 在 schema 迁移完成后，将 lion_users 自增起点校准到
// lionUsersIDStart。表尚不存在或语句执行失败仅告警，不阻断启动。
func (c *LocalConfig) ensureLionUsersIDStart(ctx context.Context, db *sql.DB) {
	stmt, err := lionUsersIDStartStmt(c.Database.Driver)
	if err != nil {
		pklogging.OrFallback(c.logger).WarnContext(ctx, "lion users id start unsupported driver", "driver", c.Database.Driver)
		return
	}

	if _, err := db.ExecContext(ctx, stmt); err != nil {
		pklogging.OrFallback(c.logger).WarnContext(ctx, "ensure lion_users id start error", "error", err)
	}
}

// initDatabase 用于初始化数据库
func (c *LocalConfig) initDatabase(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if c.Database == nil {
		c.Database = &DatabaseConfig{Enable: false}
	}

	if !c.Database.Enable {
		return nil
	}

	if c.Database.DBName == "" || c.Database.Username == "" || c.Database.Password == "" {
		return ErrDatabaseParamsMust
	}

	protocol := c.Database.Protocol
	address := c.Database.Address
	parameters := c.Database.Parameters

	if protocol == "" {
		protocol = "tcp"
	}
	if parameters == "" {
		parameters = ""
	}

	var dataSourceName string

	switch c.Database.Driver {
	case DatabaseDriverMysql:
		if address == "" {
			address = "127.0.0.1:3306"
		}
		dataSourceName = fmt.Sprintf("%s:%s@%s(%s)/%s?%s",
			c.Database.Username, c.Database.Password, protocol, address, c.Database.DBName, parameters)
	case DatabaseDriverPostgresql:
		if address == "" {
			address = "127.0.0.1:5432"
		}
		dataSourceName = fmt.Sprintf("postgres://%s:%s@%s/%s?%s",
			c.Database.Username, c.Database.Password, address, c.Database.DBName, parameters)
	default:
		return ErrDatabaseNotSupportDriver
	}

	db, err := sql.Open(c.Database.Driver, dataSourceName)
	if err != nil {
		return err
	}

	maxLifeTime := c.Database.ConnectionPool.MaxLifeTime
	maxIdleTime := c.Database.ConnectionPool.MaxIdleTime
	maxIdleConns := c.Database.ConnectionPool.MaxIdleConns
	maxOpenConns := c.Database.ConnectionPool.MaxOpenConns

	if maxIdleTime.Seconds() == 0 {
		maxIdleTime = 30 * time.Minute
	}
	if maxLifeTime.Seconds() == 0 {
		maxLifeTime = 6 * time.Hour
	}
	if maxIdleConns == 0 {
		maxIdleConns = 3
	}

	db.SetConnMaxLifetime(maxLifeTime)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxIdleTime(maxIdleTime)
	db.SetMaxOpenConns(maxOpenConns)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return err
	}

	c.Database.db = db

	// TODO; 这里用于测试 lion 数据库
	// c.testDatabaseLion()

	return nil
}

// GetDatabase 获取数据库实例
func (c *LocalConfig) GetDatabase() (*sql.DB, error) {
	if !c.Database.Enable {
		return nil, ErrDatabaseNotEnable
	}

	if c.Database.db == nil {
		return nil, ErrDatabaseNotInit
	}

	return c.Database.db, nil
}

// GetDatabaseEntSQLDriver 获取以 ent 框架的数据库模型实例
func (c *LocalConfig) GetDatabaseEntSQLDriver() (*entsql.Driver, error) {
	db, err := c.GetDatabase()
	if err != nil {
		return nil, err
	}

	return entsql.OpenDB(c.Database.Driver, db), nil
}

func dropLegacyLionAuthzTables(ctx context.Context, db *sql.DB) error {
	for _, tableName := range legacyLionAuthzTables {
		if _, err := db.ExecContext(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", tableName)); err != nil {
			return err
		}
	}
	return nil
}

// GetAdminDatabaseLion 用于测试 Lion 配置
// TODO: 这里用于测试 lion 数据库
func (c *LocalConfig) GetAdminDatabaseLion() (*lion.Client, error) {
	return c.getAdminDatabaseLion(context.Background())
}

func (c *LocalConfig) getAdminDatabaseLion(ctx context.Context) (*lion.Client, error) {
	if c.lionClient != nil {
		return c.lionClient, nil
	}

	rawDB, err := c.GetDatabase()
	if err != nil {
		return nil, err
	}
	if err := dropLegacyLionAuthzTables(ctx, rawDB); err != nil {
		return nil, err
	}

	driver, err := c.GetDatabaseEntSQLDriver()
	if err != nil {
		return nil, err
	}

	db := lion.NewClient(lion.Driver(driver))
	if err = db.Schema.Create(ctx); err != nil {
		pklogging.OrFallback(c.logger).WarnContext(ctx, "lion migrate error", "error", err)
	}

	// 迁移完成后校准 lion_users 自增起点（表存在时生效，失败仅告警）
	c.ensureLionUsersIDStart(ctx, rawDB)

	return db, nil
}
