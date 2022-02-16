package cfg

import (
    "fmt"
    "math/rand"
    "testing"
    "time"

    "github.com/opentracing/opentracing-go"
    "github.com/spf13/viper"
)

var lc *LocalConfig

func TestConfig(t *testing.T) {
    var err error

    viper.SetConfigType("yaml")
    viper.SetConfigFile("app-sample.yaml")

    if err := viper.ReadInConfig(); err != nil {
        t.Errorf("Load config file err: %v\n", err)
    }

    lc, err = New(viper.GetViper())
    if err != nil {
        t.Errorf("Load config file err: %v\n", err)
    }

    if lc.Services.Namespace != "example" {
        t.Errorf("service.Namespace != example")
    }

    t.Run("testServiceName", testServiceName)
    t.Run("testInitLogger", testLogger)
    t.Run("testInitOpenTracing", testOpenTracing)
    t.Run("testCloudEventsValue", testCloudEventsValue)
    t.Run("testCloudEventsParse", testCloudEventsParse)
    // t.Run("testServiceGRPCAddress", testServiceGRPCAddress)
}

func testServiceName(t *testing.T) {
    serviceName := "cmdb.v1.commons.api.grpc-kit.com"
    if serviceName != fmt.Sprintf("%v.%v", lc.Services.ServiceCode, lc.Services.APIEndpoint) {
        t.Errorf("service_name not match")
    }
}

func testLogger(t *testing.T) {
    lo, err := lc.InitLogger()
    if err != nil {
        t.Errorf("Init logger err: %v\n", err)
    }

    lo.Info("hello test")
}

func testOpenTracing(t *testing.T) {
    closer, err := lc.InitOpenTracing()
    if err != nil {
        t.Errorf("Init OpenTracing err: %v\n", err)
    }
    defer closer.Close()

    rand.Seed(time.Now().UnixNano())

    tracer := opentracing.GlobalTracer()
    rootSpan := tracer.StartSpan("Hello_RootSpan")

    for i := 0; i <= 2; i++ {
        var csp opentracing.Span
        if i == 1 {
            csp = opentracing.StartSpan(fmt.Sprintf("FollowsFrom_%v", i), opentracing.FollowsFrom(rootSpan.Context()))
        } else {
            csp = opentracing.StartSpan(fmt.Sprintf("ChildOf_%v", i), opentracing.ChildOf(rootSpan.Context()))
        }

        randInt := rand.Intn(100)
        csp.SetTag("process_time", randInt)
        time.Sleep(time.Duration(randInt) * time.Millisecond)

        for j := 0; j <= 1; j++ {

            var fsp opentracing.Span
            if j == 1 {
                fsp = opentracing.StartSpan(fmt.Sprintf("FollowsFrom_%v", j), opentracing.FollowsFrom(csp.Context()))
            } else {
                fsp = opentracing.StartSpan(fmt.Sprintf("ChildOf_%v", j), opentracing.ChildOf(csp.Context()))
            }

            randInt := rand.Intn(100)
            fsp.SetTag("process_time", randInt)
            time.Sleep(time.Duration(randInt) * time.Millisecond)

            fsp.SetTag("follows_key", fmt.Sprintf("%v", j))
            fsp.Finish()

            go func() {
                for x := 0; x <= 1; x++ {
                    var xsp opentracing.Span
                    if x == 1 {
                        xsp = opentracing.StartSpan(fmt.Sprintf("FollowsFrom_%v", x), opentracing.FollowsFrom(fsp.Context()))
                    } else {
                        xsp = opentracing.StartSpan(fmt.Sprintf("ChildOf_%v", x), opentracing.ChildOf(fsp.Context()))
                    }

                    randInt := rand.Intn(100)
                    xsp.SetTag("process_time", randInt)
                    time.Sleep(time.Duration(randInt) * time.Millisecond)

                    xsp.Finish()
                }
            }()
        }

        csp.Finish()
    }

    rootSpan.Finish()

    // time.Sleep(3 * time.Second)
}

/*
func testServiceGRPCAddress(t *testing.T) {
	address, port, err := lc.Services.GetGRPCListenHostPort()
	if err != nil {
		t.Errorf("err: %v", err)
	}

	fmt.Println("grpc-host:", address, "grpc-port:", port)
}
*/
