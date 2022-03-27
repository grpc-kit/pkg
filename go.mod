module github.com/grpc-kit/pkg

go 1.16

require (
	github.com/HdrHistogram/hdrhistogram-go v1.1.2 // indirect
	github.com/Shopify/sarama v1.32.0
	github.com/cloudevents/sdk-go/protocol/kafka_sarama/v2 v2.8.0
	github.com/cloudevents/sdk-go/v2 v2.8.0
	github.com/coreos/go-oidc/v3 v3.1.0
	github.com/go-sql-driver/mysql v1.6.0
	github.com/gogo/gateway v1.1.0
	github.com/gogo/protobuf v1.3.2
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/golang/protobuf v1.5.2
	github.com/google/uuid v1.1.2
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.0
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/grpc-ecosystem/grpc-gateway v1.16.0
	github.com/lib/pq v1.10.4
	github.com/mitchellh/mapstructure v1.4.3
	github.com/opentracing-contrib/go-stdlib v1.0.0
	github.com/opentracing/opentracing-go v1.1.0
	github.com/prometheus/client_golang v1.11.0
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/viper v1.10.1
	github.com/uber/jaeger-client-go v2.30.0+incompatible
	github.com/uber/jaeger-lib v2.4.1+incompatible // indirect
	github.com/xdg/scram v1.0.5
	go.etcd.io/etcd/api/v3 v3.5.2
	go.etcd.io/etcd/client/pkg/v3 v3.5.2
	go.etcd.io/etcd/client/v3 v3.5.2
	google.golang.org/grpc v1.43.0
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/apimachinery v0.23.4
)

replace google.golang.org/grpc => google.golang.org/grpc v1.38.0
