package cfg

import (
	"fmt"
	"testing"
)

func testCloudEventsParse(t *testing.T) {
	c := lc.CloudEvents.KafkaSarama.Config.Parse()
	if err := c.Validate(); err != nil {
		t.Errorf("cloudevents kafka_sarama parse err = %v", err)
	}
}

func testCloudEventsValue(t *testing.T) {
	switch lc.CloudEvents.Protocol {
	case "kafka_sarama":
	default:
		t.Errorf("cloudevents protocol %v not support", lc.CloudEvents.Protocol)
	}

	if lc.CloudEvents.KafkaSarama.Topic != "uptime-test" {
		t.Errorf("cloudevents.kafka_sarama.topic != 'uptime-test', value = '%v'", lc.CloudEvents.KafkaSarama.Topic)
	}
	if len(lc.CloudEvents.KafkaSarama.Brokers) != 3 {
		t.Errorf("cloudevents.kafka_sarama.brokers length != '3', value = '%v'", len(lc.CloudEvents.KafkaSarama.Brokers))
	}

	diffValue(t, "net.max_open_requests", "5",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Net.MaxOpenRequests))
	diffValue(t, "net.dial_timeout", "30s",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Net.DialTimeout))
	diffValue(t, "net.read_timeout", "30s",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Net.ReadTimeout))
	diffValue(t, "net.write_timeout", "30s",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Net.WriteTimeout))
	diffValue(t, "net.tls.enable", "false",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Net.TLS.Enable))
	diffValue(t, "net.sasl.enable", "true",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Net.SASL.Enable))
	diffValue(t, "net.sasl.mechanism", "SCRAM-SHA-256",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Net.SASL.Mechanism))
	diffValue(t, "net.sasl.user", "uptime",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Net.SASL.User))
	diffValue(t, "net.sasl.password", "testkey",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Net.SASL.Password))
	diffValue(t, "net.keep_alive", "40s",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Net.KeepAlive))
	diffValue(t, "metadata.retry.max", "3",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Metadata.Retry.Max))
	diffValue(t, "metadata.retry.backoff", "250ms",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Metadata.Retry.Backoff))
	diffValue(t, "metadata.refresh_frequency", "10m0s",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Metadata.RefreshFrequency))
	diffValue(t, "metadata.full", "true",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Metadata.Full))
	diffValue(t, "metadata.allow_auto_topic_creation", "false",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Metadata.AllowAutoTopicCreation))
	diffValue(t, "producer.max_message_bytes", "1000000",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Producer.MaxMessageBytes))
	diffValue(t, "producer.required_acks", "1",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Producer.RequiredAcks))
	diffValue(t, "producer.timeout", "10s",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Producer.Timeout))
	diffValue(t, "producer.return.successes", "false",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Producer.Return.Successes))
	diffValue(t, "producer.return.errors", "true",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Producer.Return.Errors))
	diffValue(t, "producer.flush.bytes", "104857600",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Producer.Flush.Bytes))
	diffValue(t, "producer.retry.max", "3",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Producer.Retry.Max))
	diffValue(t, "producer.retry.backoff", "100ms",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Producer.Retry.Backoff))
	diffValue(t, "consumer.group.session.timeout", "10s",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Consumer.Group.Session.Timeout))
	diffValue(t, "consumer.group.heartbeat.interval", "3s",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Consumer.Group.Heartbeat.Interval))
	diffValue(t, "consumer.group.rebalance.strategy", "range",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Consumer.Group.Rebalance.Strategy))
	diffValue(t, "consumer.group.rebalance.timeout", "55s",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Consumer.Group.Rebalance.Timeout))
	diffValue(t, "consumer.group.rebalance.retry.max", "4",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Consumer.Group.Rebalance.Retry.Max))
	diffValue(t, "consumer.group.rebalance.retry.backoff", "2s",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Consumer.Group.Rebalance.Retry.Backoff))
	diffValue(t, "consumer.group.retry.backoff", "2s",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Consumer.Retry.Backoff))
	diffValue(t, "consumer.fetch.min", "1",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Consumer.Fetch.Min))
	diffValue(t, "consumer.max_wait_time", "250ms",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Consumer.MaxWaitTime))
	diffValue(t, "consumer.max_processing_time", "100ms",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Consumer.MaxProcessingTime))
	diffValue(t, "consumer.return.errors", "true",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Consumer.Return.Errors))
	diffValue(t, "consumer.offsets.auto_commit.enable", "true",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Consumer.Offsets.AutoCommit.Enable))
	diffValue(t, "consumer.offsets.auto_commit.interval", "1s",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Consumer.Offsets.AutoCommit.Interval))
	diffValue(t, "consumer.offsets.retry.max", "3",
		fmt.Sprintf("%v", lc.CloudEvents.KafkaSarama.Config.Consumer.Offsets.Retry.Max))
}

func diffValue(t *testing.T, key, expect, current string) {
	if expect != current {
		t.Errorf("cloudevents.kafka_sarama.config.%v expect value '%v', current value '%v'", key, expect, current)
	}
}
