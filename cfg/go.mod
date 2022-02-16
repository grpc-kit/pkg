module github.com/grpc-kit/pkg/cfg

go 1.13

require (
	github.com/Shopify/sarama v1.31.1
	github.com/cloudevents/sdk-go/protocol/kafka_sarama/v2 v2.8.0
	github.com/cloudevents/sdk-go/v2 v2.8.0
	github.com/codahale/hdrhistogram v0.0.0-20161010025455-3a0bb77429bd // indirect
	github.com/coreos/go-oidc/v3 v3.0.0
	github.com/gogo/gateway v1.1.0
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/golang/protobuf v1.4.3
	github.com/google/uuid v1.1.2
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.0
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/grpc-ecosystem/grpc-gateway v1.13.0
	github.com/grpc-kit/api v0.0.0-20200430142535-fa4f5e68cf77
	github.com/grpc-kit/pkg v0.1.3
	github.com/mitchellh/mapstructure v1.1.2
	github.com/opentracing-contrib/go-stdlib v0.0.0-20190519235532-cf7a6c988dc9
	github.com/opentracing/opentracing-go v1.1.0
	github.com/prometheus/client_golang v1.4.1
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/viper v1.6.2
	github.com/uber/jaeger-client-go v2.22.1+incompatible
	github.com/uber/jaeger-lib v2.2.0+incompatible // indirect
	github.com/xdg/scram v1.0.5
	github.com/xdg/stringprep v1.0.3 // indirect
	google.golang.org/grpc v1.27.0
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/apimachinery v0.21.1
)

replace google.golang.org/grpc => google.golang.org/grpc v1.26.0
