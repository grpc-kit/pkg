package cfg

import (
	"fmt"
	"testing"

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

	if lc.Services.Namespace != "default" {
		t.Errorf("service.Namespace != default")
	}

	t.Run("testServiceName", testServiceName)
	t.Run("testInitLogger", testLogger)
	// t.Run("testInitOpenTracing", testOpenTracing)
	t.Run("testCloudEventsValue", testCloudEventsValue)
	t.Run("testCloudEventsParse", testCloudEventsParse)
	// t.Run("testServiceGRPCAddress", testServiceGRPCAddress)
}

func testServiceName(t *testing.T) {
	serviceName := "test1.v1.opsaid.api.grpc-kit.com"
	if serviceName != fmt.Sprintf("%v.%v", lc.Services.ServiceCode, lc.Services.APIEndpoint) {
		t.Errorf("service_name not match")
	}
}

func testLogger(t *testing.T) {
	err := lc.InitDebugger()
	if err != nil {
		t.Errorf("Init logger err: %v\n", err)
	}

	lo := lc.GetLogger()
	lo.Info("hello test")
}

/*
func testOpenTracing(t *testing.T) {
	ctx := context.TODO()

	_, err := lc.InitOpentracing()
	if err != nil {
		t.Errorf("Init OpenTracing err: %v\n", err)
	}
	// defer closer.Close()

	rand.Seed(time.Now().UnixNano())

	tr := otel.Tracer("testOpenTracing")
	rootCtx, rootSpan := tr.Start(ctx, "Hello_RootSpan")

	for i := 0; i <= 2; i++ {
		var csp trace.Span
		if i == 1 {
			// csp = opentracing.StartSpan(fmt.Sprintf("FollowsFrom_%v", i), opentracing.FollowsFrom(rootCtx))
			tr.Start(rootCtx, fmt.Sprintf("FollowsFrom_%v", i))
		} else {
			// csp = opentracing.StartSpan(fmt.Sprintf("ChildOf_%v", i), opentracing.ChildOf(rootCtx))
			tr.Start(rootCtx, fmt.Sprintf("ChildOf_%v", i))
		}

		randInt := rand.Intn(100)
		csp.SetAttributes(attribute.Int("process_time", randInt))
		time.Sleep(time.Duration(randInt) * time.Millisecond)

		for j := 0; j <= 1; j++ {

			var fsp trace.Span
			if j == 1 {
				_, fsp = tr.Start(trace.ContextWithSpan(rootCtx, rootSpan), fmt.Sprintf("FollowsFrom_%v", j))
				//fsp = opentracing.StartSpan(fmt.Sprintf("FollowsFrom_%v", j), opentracing.FollowsFrom(csp.Context()))
			} else {
				_, fsp = tr.Start(trace.ContextWithSpan(rootCtx, rootSpan), fmt.Sprintf("ChildOf_%v", j))
			}

			randInt := rand.Intn(100)
			// fsp.SetTag("process_time", randInt)
			time.Sleep(time.Duration(randInt) * time.Millisecond)

			// fsp.SetTag("follows_key", fmt.Sprintf("%v", j))
			fsp.End()

		}

		csp.End()
	}

	rootSpan.End()
}
*/

func configKeydiffValue(t *testing.T, prefix, key string, expect, current interface{}) {
	if expect != current {
		t.Errorf("%v.%v expect value '%v', current value '%v'", prefix, key, expect, current)
	}
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
