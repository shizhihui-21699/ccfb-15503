package source

import (
	"context"
	"time"

	"powfence/internal/metric"
)

// Mock is a deterministic, controllable telemetry source.
//
// It serves three purposes:
//  1. unit tests and offline demos without root or hardware access;
//  2. the self-test attack simulator, which drives it via SetKeySignal;
//  3. a reference for the exact semantics a real Source must implement
//     (cumulative joules, wrap-free counters, timestamped samples).
//
// The mock is deterministic: it uses a logical tick clock advanced by
// TickInterval rather than wall time, so test results are reproducible.
type Mock struct {
	TickInterval time.Duration
	Nominal      float64
	Max          float64

	// BaselineW is the package power with no injected signal.
	BaselineW float64
	// BaselineMHz is the frequency with no injected signal.
	BaselineMHz float64

	// SignalW / SignalMHz are the current key-dependent deviations applied
	// on top of the baselines. SetKeySignal updates them; the self-test
	// alternates them per "operation" to simulate key-bit-dependent leakage.
	SignalW   float64
	SignalMHz float64

	// CPUs is the number of logical CPUs reported in frequency samples.
	CPUs int

	tick     int
	energyJ  float64
	baseTime time.Time
}

// NewMock builds a mock with realistic defaults for a ~250 W TDP socket.
func NewMock() *Mock {
	return &Mock{
		TickInterval: 100 * time.Millisecond,
		Nominal:      2500,
		Max:          3500,
		BaselineW:    120,
		BaselineMHz:  2800,
		CPUs:         8,
		baseTime:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// SetKeySignal programs the current key-dependent leakage. Values are
// deviations from baseline (may be negative).
func (m *Mock) SetKeySignal(powerW, freqMHz float64) {
	m.SignalW = powerW
	m.SignalMHz = freqMHz
}

func (m *Mock) now() time.Time {
	return m.baseTime.Add(time.Duration(m.tick) * m.TickInterval)
}

// Collect advances the logical clock by one tick and emits a batch.
func (m *Mock) Collect(_ context.Context) (metric.RawBatch, error) {
	dt := m.TickInterval.Seconds()
	power := m.BaselineW + m.SignalW
	m.energyJ += power * dt
	t := m.now()
	m.tick++

	batch := metric.RawBatch{
		Counters: []metric.RawCounter{{
			Domain: "package-0",
			Joules: m.energyJ,
			T:      t,
		}},
		Frequencies: make([]metric.RawFrequency, 0, m.CPUs),
	}
	freq := m.BaselineMHz + m.SignalMHz
	for cpu := 0; cpu < m.CPUs; cpu++ {
		batch.Frequencies = append(batch.Frequencies, metric.RawFrequency{
			CPU: cpu,
			MHz: freq,
			T:   t,
		})
	}
	return batch, nil
}

func (m *Mock) NominalMHz() float64 { return m.Nominal }
func (m *Mock) MaxMHz() float64     { return m.Max }
func (m *Mock) Close() error        { return nil }
