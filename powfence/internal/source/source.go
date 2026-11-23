// Package source abstracts host hardware telemetry collection.
//
// The rest of the proxy depends only on the Source interface. Two backends
// exist: a deterministic Mock used by tests, demos and the self-test attack
// simulator, and a Linux RAPL/sysfs backend used in production.
package source

import (
	"context"

	"powfence/internal/metric"
)

// Source polls raw hardware telemetry. Implementations must be safe for
// concurrent use and must never expose per-core/per-domain data through any
// other channel than Collect.
type Source interface {
	// Collect returns one batch of raw samples taken approximately at time
	// "now". The sanitizer owns all aggregation and release decisions.
	Collect(ctx context.Context) (metric.RawBatch, error)

	// NominalMHz / MaxMHz report static CPUID-derived frequencies. These are
	// not secret and are also what tenants receive in nominal-only mode.
	NominalMHz() float64
	MaxMHz() float64

	// Close releases file descriptors / goroutines.
	Close() error
}
