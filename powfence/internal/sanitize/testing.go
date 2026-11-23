package sanitize

import (
	"time"

	"powfence/internal/dp"
	"powfence/internal/policy"
)

// TickForTest is the exported shape used by the self-test simulator to
// inject pre-aggregated ticks. It mirrors the private tick struct.
type TickForTest struct {
	Seq     uint64
	T       time.Time
	EnergyJ float64
	FreqMHz float64
}

// PushForTest inserts a synthetic tick. Production code always goes through
// Collector; this entry point exists so the attack simulator is reproducible
// without hardware and without manipulating private types.
func (r *Ring) PushForTest(t TickForTest) {
	r.push(tick{
		seq:     t.Seq,
		t:       t.T,
		energyJ: t.EnergyJ,
		freqMHz: t.FreqMHz,
	})
}

// NewForTest constructs a sanitizer without a live metric source, for
// offline evaluation. The nominal/max arguments are accepted to keep call
// sites self-documenting; the effective static frequencies come from the
// policy's Frequency section.
func NewForTest(pol *policy.Policy, ring *Ring, rng dp.Rand, nominal, max float64) *Sanitizer {
	_ = nominal
	_ = max
	return New(pol, ring, rng)
}
