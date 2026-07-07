package cfg

import (
	"fmt"
	"os"
	"testing"

	"github.com/spf13/viper"
)

const cfgDatabaseIntegrationEnv = "GRPC_KIT_CFG_DB_INTEGRATION"

func TestDatabase(t *testing.T) {
	ensureTestLocalConfig(t)
	t.Run("testDatabaseConfig", testDatabaseConfig)
	t.Run("testDatabaseInit", testDatabaseInit)
}

func ensureTestLocalConfig(t *testing.T) {
	t.Helper()
	if lc != nil {
		return
	}

	v := viper.New()
	v.SetConfigType("yaml")
	v.SetConfigFile("app-sample.yaml")
	if err := v.ReadInConfig(); err != nil {
		t.Fatalf("load config file err: %v", err)
	}

	var err error
	lc, err = New(v)
	if err != nil {
		t.Fatalf("load config file err: %v", err)
	}
}

func testDatabaseInit(t *testing.T) {
	if os.Getenv(cfgDatabaseIntegrationEnv) == "" {
		t.Skipf("skip external database integration test; set %s=1 to enable", cfgDatabaseIntegrationEnv)
	}
	if err := lc.initDatabase(); err != nil {
		t.Errorf("database init err=%v", err)
	}
}

func testDatabaseConfig(t *testing.T) {
	switch lc.Database.Driver {
	case DatabaseDriverMysql:
	case DatabaseDriverPostgresql:
	default:
		t.Error(ErrDatabaseNotSupportDriver)
	}

	if lc.Database.DBName == "" || lc.Database.Username == "" || lc.Database.Password == "" {
		t.Error(ErrDatabaseParamsMust)
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
	if os.Getenv(cfgDatabaseIntegrationEnv) == "" {
		b.Skipf("skip external database benchmark; set %s=1 to enable", cfgDatabaseIntegrationEnv)
	}
	if err := lc.initDatabase(); err != nil {
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
