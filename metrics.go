package main

import (
	"context"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	secretsCreated = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "burn_after_reading_secrets_created_total",
		Help: "Secrets stored.",
	}, []string{"alg"})
	secretsConsumed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "burn_after_reading_secrets_consumed_total",
		Help: "Secrets fetched and deleted.",
	}, []string{"alg"})
	secretsExpired = promauto.NewCounter(prometheus.CounterOpts{
		Name: "burn_after_reading_secrets_expired_total",
		Help: "Secrets deleted by the pruner without being read.",
	})
)

func init() {
	// Create every series at zero so rate() and increase() work from the
	// start instead of the first event.
	for _, alg := range []byte{algPGPAES, algXChaCha} {
		secretsCreated.WithLabelValues(algName(alg))
		secretsConsumed.WithLabelValues(algName(alg))
	}
}

// ServeMetrics serves /metrics on its own port, so it is never exposed
// through the public route.
func ServeMetrics(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.Handler())
	return runServer(ctx, &http.Server{Addr: ":9090", Handler: mux})
}
