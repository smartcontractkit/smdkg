package testimplementations

import "github.com/prometheus/client_golang/prometheus"

type TestMetricsRegisterer struct{}

func (tm TestMetricsRegisterer) Register(collector prometheus.Collector) error {
	return nil
}

func (tm TestMetricsRegisterer) MustRegister(collectors ...prometheus.Collector) {}

func (tm TestMetricsRegisterer) Unregister(collector prometheus.Collector) bool {
	return true
}
