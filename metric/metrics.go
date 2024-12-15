package metric

import "github.com/prometheus/client_golang/prometheus"

var (
	namespace = "oauthx_client"

	OAuthSuccessRateCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "call",
			Help:      "Number of oauth2 call outcome per endpoint",
		},
		[]string{
			"oauth_endpoint",
			"outcome",
		},
	)

	OAuthDurationHist = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "call_dur",
			Help:      "Histogram for the duration of oauth2 call",
			// Buckets:   prometheus.ExponentialBuckets(0.1, 1.5, 5),
		},
		[]string{"oauth_endpoint"},
	)
)

func init() {
	PrometheusMetricsRegister()
}

// PrometheusMetricsRegister Register metrics with prometheus
func PrometheusMetricsRegister() {
	// Metrics have to be registered to be exposed:
	prometheus.MustRegister(OAuthDurationHist)
	prometheus.MustRegister(OAuthSuccessRateCounter)
}

func MonitorError(endpoint string, err error) {

	outcome := "success"
	if err != nil {
		outcome = "failure"
	}

	MonitorOutcome(endpoint, outcome)
}

func DeferMonitorError(endpoint string, err *error) {

	outcome := "success"
	if *err != nil {
		outcome = "failure"
	}

	MonitorOutcome(endpoint, outcome)
}

func MonitorOutcome(endpoint, outcome string) {

	OAuthSuccessRateCounter.With(prometheus.Labels{
		"oauth_endpoint": endpoint,
		"outcome":        outcome,
	}).Inc()
}
