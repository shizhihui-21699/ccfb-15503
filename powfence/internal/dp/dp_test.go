package dp

import (
	"math"
	"testing"
)

// deterministicRand returns a scripted sequence for exact assertions.
type deterministicRand struct {
	values []float64
	idx    int
}

func (d *deterministicRand) Float64() float64 {
	v := d.values[d.idx%len(d.values)]
	d.idx++
	return v
}

func TestLaplaceScaleAndMean(t *testing.T) {
	if got := LaplaceScale(3, 0.5); got != 6 {
		t.Fatalf("scale = %v, want 6", got)
	}

	// Scripted uniforms: Laplace consumes two draws per sample (magnitude
	// then sign). v=0.5 gives magnitude b*ln(0.5); the sign draw decides
	// the direction. Two opposite-sign draws must sum to zero.
	r := &deterministicRand{values: []float64{
		0.5, 0.1, // draw 1: sign draw < 0.5 -> +b*ln(0.5)
		0.5, 0.9, // draw 2: sign draw >= 0.5 -> -b*ln(0.5)
	}}
	b := 2.0
	x1 := Laplace(r, b)
	x2 := Laplace(r, b)
	if math.Abs((x1+x2)-0) > 1e-12 {
		t.Fatalf("opposite-sign draws did not cancel: %v + %v", x1, x2)
	}
	if math.Abs(math.Abs(x1)-b*math.Abs(math.Log(0.5))) > 1e-12 {
		t.Fatalf("magnitude = %v, want %v", math.Abs(x1), b*math.Abs(math.Log(0.5)))
	}
}

func TestLaplacePanicsOnBadInputs(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for non-positive epsilon")
		}
	}()
	LaplaceScale(1, 0)
}

func TestLaplaceDistributionProperties(t *testing.T) {
	// A seeded ChaCha8 source: verify empirical mean ~= 0 and empirical
	// variance ~= 2b^2 over many draws.
	r := SeedFromBytes([32]byte{1, 2, 3})
	const b = 1.5
	const n = 200000
	var sum, sumSq float64
	for range n {
		x := Laplace(r, b)
		sum += x
		sumSq += x * x
	}
	mean := sum / n
	variance := sumSq/n - mean*mean
	wantVar := 2 * b * b
	if math.Abs(mean) > 0.05 {
		t.Errorf("mean = %v, want ~0", mean)
	}
	if rel := math.Abs(variance-wantVar) / wantVar; rel > 0.05 {
		t.Errorf("variance = %v, want ~%v (rel error %.2f)", variance, wantVar, rel)
	}
}

func TestQuantize(t *testing.T) {
	cases := []struct {
		x, step, want float64
	}{
		{2.3, 1, 2}, {2.6, 1, 3}, {0.7, 0.5, 0.5}, {1.25, 0.5, 1.5}, {4.9, 0, 4.9},
	}
	for _, c := range cases {
		if got := Quantize(c.x, c.step); got != c.want {
			t.Errorf("Quantize(%v,%v) = %v, want %v", c.x, c.step, got, c.want)
		}
	}
}

func TestClip(t *testing.T) {
	if Clip(-1, 0, 10) != 0 || Clip(11, 0, 10) != 10 || Clip(5, 0, 10) != 5 {
		t.Error("clip bounds violated")
	}
}

func TestLedgerRolloverAndRejection(t *testing.T) {
	l := NewLedger(1.0, 100, 1000)
	if !l.TryCharge(0.6, 1000) {
		t.Fatal("first charge should fit")
	}
	if l.TryCharge(0.5, 1000) {
		t.Fatal("charge exceeding budget must be refused")
	}
	if !l.TryCharge(0.4, 1000) {
		t.Fatal("charge fitting remaining budget should pass")
	}
	if math.Abs(l.Spent()-1.0) > 1e-12 {
		t.Fatalf("spent = %v, want 1.0", l.Spent())
	}
	// Epoch rollover resets the counter.
	if !l.TryCharge(0.9, 1100) {
		t.Fatal("charge after rollover must be allowed")
	}
	if math.Abs(l.Spent()-0.9) > 1e-12 {
		t.Fatalf("post-rollover spent = %v, want 0.9", l.Spent())
	}
}

func TestSensitivityModes(t *testing.T) {
	if got := EnergySensitivityJ("full_range", 1.5, 250, 2); got != 500 {
		t.Errorf("full-range energy sensitivity = %v, want 500", got)
	}
	if got := EnergySensitivityJ("signal_bounded", 0.05, 250, 2); got != 0.05 {
		t.Errorf("signal-bounded energy sensitivity = %v, want 0.05", got)
	}
	if got := FrequencySensitivityMHz("full_range", 3, 3500); got != 3500 {
		t.Errorf("full-range freq sensitivity = %v, want 3500", got)
	}
}
