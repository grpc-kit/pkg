package sd

import (
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver"
)

var (
	logger = logrus.WithField("service", "test")
)

func TestRegisterDemo1(t *testing.T) {
	hosts := "http://127.0.0.1:2379,http://127.0.0.1:2379,http://127.0.0.1:2379"
	conns, err := NewConnector(logger, ETCDV3, hosts)
	if err != nil {
		fmt.Println("err:", err)
	}

	Home("service", "default")
	cli, err := Register(conns, "com.example.grpc.demo.v1.Demo1", "127.0.0.1:20088", "", 2)
	if err != nil {
		fmt.Println("register err:", err)
	}

	time.Sleep(1000 * time.Second)

	if err := cli.Deregister(); err != nil {
		fmt.Println("deregister err:", err)
	}

	fmt.Println("deregister Demo1")
}

func TestRegisterDemo2(t *testing.T) {
	hosts := "http://127.0.0.1:2379,http://127.0.0.1:2379,http://127.0.0.1:2379"
	conns, err := NewConnector(logger, ETCDV3, hosts)
	if err != nil {
		fmt.Println("err:", err)
	}

	Home("service", "default")
	_, err = Register(conns, "com.example.grpc.demo.v1.Demo2", "127.0.0.1:20089", "", 100)
	if err != nil {
		fmt.Println("register err:", err)
	}

	// time.Sleep(10 * time.Second)

	/*
		if err := cli.Deregister(); err != nil {
			fmt.Println("deregister err:", err)
		}
	*/

	fmt.Println("deregister Demo2")
}

func TestResolver(t *testing.T) {
	hosts := "http://127.0.0.1:2379,http://127.0.0.1:2379,http://127.0.0.1:2379"
	conns, err := NewConnector(logger, ETCDV3, hosts)
	if err != nil {
		fmt.Println("err:", err)
	}

	Home("service", "default")
	r := NewResolver(conns)
	resolver.Register(r)

	target := fmt.Sprintf("%v://default/%v", r.Scheme(), "com.example.grpc.demo.v1.Demo2")

	conn, err := grpc.Dial(target, grpc.WithBalancerName("round_robin"), grpc.WithInsecure())
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Println("target:", conn.GetState().String())
}
