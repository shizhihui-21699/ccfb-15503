// Package metric defines the hardware telemetry types that flow through the
// proxy. The raw types are host-internal; only the sanitized Reading type is
// ever serialized to a tenant.
package metric

import "time"

// RawCounter is a single hardware energy counter snapshot at time T.
// Counters are monotonic between wraps; the source layer normalizes wraps
// away so downstream code only sees increasing values.
type RawCounter struct {
	// Domain identifies the RAPL domain, e.g. "package-0", "psys".
	Domain string
	// Joules is the cumulative counter value.
	Joules float64
	// T is the kernel-side sampling timestamp.
	T time.Time
}

// RawFrequency is one instantaneous CPU frequency sample.
type RawFrequency struct {
	CPU int
	MHz float64
	T   time.Time
}

// RawBatch is everything the source collected in one polling tick.
type RawBatch struct {
	Counters    []RawCounter
	Frequencies []RawFrequency
}

// Reading is the ONLY shape a tenant can observe. Fields absent from a policy
// are left at zero and omitted by JSON tags.
type Reading struct {
	// WindowStart/WindowEnd identify the aggregation window. Repeated polls
	// inside the same window return identical timestamps and values.
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`

	// EnergyJ is the released (aggregated, clipped, noised, quantized)
	// energy increment over the window.
	EnergyJ *float64 `json:"energy_joules,omitempty"`
	// AveragePowerW is convenience derived from EnergyJ / window length;
	// it carries no additional information and is audited as such.
	AveragePowerW *float64 `json:"average_power_watts,omitempty"`

	// FreqMHz is the released window-average frequency.
	FreqMHz *float64 `json:"freq_mhz,omitempty"`
	// NominalMHz / MaxMHz are static CPUID values, always safe to expose.
	NominalMHz float64 `json:"nominal_mhz,omitempty"`
	MaxMHz     float64 `json:"max_mhz,omitempty"`

	// EpsilonSpent accounts privacy budget for this release and lets
	// tenants (and auditors) reproduce the composition calculation.
	EpsilonSpent float64 `json:"epsilon_spent"`
}
