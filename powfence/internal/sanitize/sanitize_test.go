package sanitize

import (
	"testing"
	"time"

	"powfence/internal/dp"
	"powfence/internal/policy"
)

func testPolicy() *policy.Policy {
	return &policy.Policy{
		Name: "t", EpochSeconds: 3600, EpochBudgetEpsilon: 360,
		RatePerSecond: 100, Burst: 100,
		Energy: policy.EnergyPolicy{
			Enabled: true, WindowSeconds: 1, QuantizeJ: 1,
			DPMode: policy.DPModeSignalBounded, SignalMaxDeltaJ: 0.05,
			EnvelopeW: 250, BudgetShare: 0.5,
		},
		Frequency: policy.FrequencyPolicy{
			Enabled: true, WindowSeconds: 1, QuantizeMHz: 25,
			DPMode: policy.DPModeSignalBounded, SignalMaxDeltaMHz: 1,
			EnvelopeMHz: 3500, NominalMHz: 2500, MaxMHz: 3500, BudgetShare: 0.5,
		},
	}
}

func pushTicks(ring *Ring, startSeq uint64, base time.Time, n int, energyJ, freq float64) {
	for k := 0; k < n; k++ {
		ring.PushForTest(TickForTest{
			Seq:     startSeq + uint64(k),
			T:       base.Add(time.Duration(k) * 100 * time.Millisecond),
			EnergyJ: energyJ,
			FreqMHz: freq,
		})
	}
}

// TestWindowCachingIsIdentical is the central anti-averaging property: two
// requests inside one window must return byte-identical values, so an
// attacker cannot harvest independent noise draws by polling fast.
func TestWindowCachingIsIdentical(t *testing.T) {
	pol := testPolicy()
	if err := pol.ValidatePolicy(); err != nil {
		t.Fatal(err)
	}
	ring := NewRing(4096)
	var seed [32]byte
	san := NewForTest(pol, ring, dp.SeedFromBytes(seed), 2500, 3500)

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pushTicks(ring, 1, base, 10, 12, 2800)

	r1, err := san.GetReading(base.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := san.GetReading(base.Add(1500 * time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if r1.EnergyJ == nil || r2.EnergyJ == nil || *r1.EnergyJ != *r2.EnergyJ {
		t.Fatalf("cached energy values differ: %v vs %v", r1.EnergyJ, r2.EnergyJ)
	}
	if r1.FreqMHz == nil || r2.FreqMHz == nil || *r1.FreqMHz != *r2.FreqMHz {
		t.Fatalf("cached frequency values differ: %v vs %v", r1.FreqMHz, r2.FreqMHz)
	}
	if !r1.WindowStart.Equal(r2.WindowStart) {
		t.Fatal("cached readings must reference the same window")
	}
}

// TestNewWindowSpendsBudget verifies each distinct window is a fresh release.
func TestNewWindowSpendsBudget(t *testing.T) {
	pol := testPolicy()
	if err := pol.ValidatePolicy(); err != nil {
		t.Fatal(err)
	}
	ring := NewRing(4096)
	var seed [32]byte
	san := NewForTest(pol, ring, dp.SeedFromBytes(seed), 2500, 3500)

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pushTicks(ring, 1, base, 10, 12, 2800)
	r1, _ := san.GetReading(base.Add(time.Second))

	pushTicks(ring, 11, base.Add(time.Second), 10, 12, 2800)
	r2, _ := san.GetReading(base.Add(2 * time.Second))

	if r1.EpsilonSpent <= 0 || r2.EpsilonSpent <= 0 {
		t.Fatal("real window releases must charge epsilon")
	}
	if *r1.EnergyJ == *r2.EnergyJ && *r1.FreqMHz == *r2.FreqMHz {
		// Extremely unlikely with independent noise draws; a deterministic
		// repeat would indicate the RNG or cache is shared incorrectly.
		t.Log("warning: consecutive windows produced identical values")
	}
}

// TestNominalOnlyIsConstant verifies the high-assurance frequency mode:
// every window returns the same static frequency regardless of workload.
func TestNominalOnlyIsConstant(t *testing.T) {
	pol := testPolicy()
	pol.Frequency.ExposeNominalOnly = true
	pol.Frequency.NominalMHz = 2600
	pol.Frequency.MaxMHz = 3400
	if err := pol.ValidatePolicy(); err != nil {
		t.Fatal(err)
	}
	ring := NewRing(4096)
	var seed [32]byte
	san := NewForTest(pol, ring, dp.SeedFromBytes(seed), 2600, 3400)

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for w := 0; w < 3; w++ {
		pushTicks(ring, uint64(1+w*10), base.Add(time.Duration(w)*time.Second),
			10, 12, 2800+float64(w*100)) // wildly varying raw frequency
		r, err := san.GetReading(base.Add(time.Duration(w+1) * time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if r.FreqMHz == nil || *r.FreqMHz != 2600 {
			t.Fatalf("window %d: nominal-only returned %v, want constant 2600", w, r.FreqMHz)
		}
	}
}

// TestSpatialAggregation confirms per-window energy is the sum of ticks and
// the mean frequency is their average - no per-core identity survives.
func TestSpatialAggregation(t *testing.T) {
	ring := NewRing(64)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pushTicks(ring, 1, base, 10, 5, 3000)
	ticks := ring.window(base, base.Add(time.Second))
	if len(ticks) != 10 {
		t.Fatalf("window returned %d ticks, want 10", len(ticks))
	}
	if got := sumEnergy(ticks); got != 50 {
		t.Errorf("summed energy = %v, want 50", got)
	}
	if got := meanFreq(ticks); got != 3000 {
		t.Errorf("mean frequency = %v, want 3000", got)
	}
}

// TestRateLimitEnforced verifies the token bucket blocks burst abuse.
func TestRateLimitEnforced(t *testing.T) {
	pol := testPolicy()
	pol.RatePerSecond = 1
	pol.Burst = 1
	if err := pol.ValidatePolicy(); err != nil {
		t.Fatal(err)
	}
	ring := NewRing(4096)
	var seed [32]byte
	san := NewForTest(pol, ring, dp.SeedFromBytes(seed), 2500, 3500)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pushTicks(ring, 1, base, 10, 12, 2800)

	if _, err := san.GetReading(base.Add(time.Second)); err != nil {
		t.Fatalf("first request: %v", err)
	}
	if _, err := san.GetReading(base.Add(time.Second + 100*time.Millisecond)); err != ErrRateLimited {
		t.Fatalf("second immediate request: got %v, want ErrRateLimited", err)
	}
}
