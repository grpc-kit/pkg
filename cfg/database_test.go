package cfg

import (
    "fmt"
    "testing"
)

func TestDatabase(t *testing.T) {
    t.Run("testDatabaseConfig", testDatabaseConfig)
    t.Run("testDatabaseInit", testDatabaseInit)
}

func testDatabaseInit(t *testing.T) {
    if err := lc.InitDatabase(); err != nil {
        t.Errorf("database init err=%v", err)
    }
}

func testDatabaseConfig(t *testing.T) {
    switch lc.Database.Driver {
    case DatabaseDriverMysql:
    case DatabaseDriverPostgresql:
    default:
        t.Errorf(ErrDatabaseNotSupportDriver.Error())
    }

    if lc.Database.DBName == "" || lc.Database.Username == "" || lc.Database.Password == "" {
        t.Errorf(ErrDatabaseParamsMust.Error())
    }

    if lc.Database.ConnectionPool.MaxIdleTime.Seconds() != 1800 {
        configKeydiffValue(t, "database.connection_pool", "max_idle_time", "30m", lc.Database.ConnectionPool.MaxIdleTime.String())
    }
    if lc.Database.ConnectionPool.MaxLifeTime.Seconds() != 21600 {
        configKeydiffValue(t, "database.connection_pool", "max_life_time", "6h", lc.Database.ConnectionPool.MaxLifeTime.String())
    }
    if lc.Database.ConnectionPool.MaxIdleConns != 300 {
        configKeydiffValue(t, "database.connection_pool", "max_idle_conns", 300, lc.Database.ConnectionPool.MaxIdleConns)
    }
    if lc.Database.ConnectionPool.MaxOpenConns != 300 {
        configKeydiffValue(t, "database.connection_pool", "max_open_conns", 300, lc.Database.ConnectionPool.MaxOpenConns)
    }
}

func BenchmarkDatabaseInsert(b *testing.B) {
    if err := lc.InitDatabase(); err != nil {
        b.Errorf("init database err=%v", err)
    }
    db, err := lc.GetDatabase()
    if err != nil {
        b.Errorf("get database err=%v", err)
    }

    createTable := `CREATE TABLE t_code(id int, code varchar(20));`
    if _, err := db.Exec(createTable); err != nil {
        b.Errorf("database create table err = %v", err)
    }

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        insertSQL := `INSERT INTO t_code(id, code) VALUES(?, ?)`
        if _, err := db.Exec(insertSQL, i, fmt.Sprintf("code-%v", i)); err != nil {
            b.Errorf("insert into err = %v", err)
        }
    }
    b.StopTimer()

    dropTable := `DROP TABLE t_code`
    if _, err := db.Exec(dropTable); err != nil {
        b.Errorf("database drop table err = %v", err)
    }

    if err := db.Close(); err != nil {
        b.Errorf("database close err = %v", err)
    }
}
