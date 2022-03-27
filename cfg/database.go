package cfg

import (
    "database/sql"
    "errors"
    "fmt"
    "time"

    _ "github.com/go-sql-driver/mysql"
    _ "github.com/lib/pq"
)

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

// InitDatabase 用于初始化数据库
func (c *LocalConfig) InitDatabase() error {
    if c.Database.Enable {
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

    if err := db.Ping(); err != nil {
        return err
    }

    c.Database.db = db

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
