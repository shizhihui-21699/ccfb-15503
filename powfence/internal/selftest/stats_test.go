package selftest

import (
	"math"
	"testing"
)

func TestAUCChanceAndPerfect(t *testing.T) {
	// Interleaved identical distributions -> AUC ~= 0.5.
	var a, b []float64
	for i := 0; i < 100; i++ {
		a = append(a, float64(i))
		b = append(b, float64(i)+0.01) // near-identical, b slightly above
	}
	auc := classifyAUC(a, b)
	if auc <= 0.5 || auc > 0.55 {
		t.Errorf("near-identical AUC = %v, want just above 0.5", auc)
	}

	// Perfect separation -> AUC 1.0.
	a, b = nil, nil
	for i := 0; i < 50; i++ {
		a = append(a, float64(i))
		b = append(b, 1000+float64(i))
	}
	if got := classifyAUC(a, b); got != 1.0 {
		t.Errorf("perfect separation AUC = %v, want 1", got)
	}
}

func TestAUCSignificanceSampleScaling(t *testing.T) {
	// Same small effect must be non-significant at small N but significant
	// at large N - the defining property of a sample-size-aware test.
	effect := 0.05
	if aucSignificant(0.5+effect, 20, 20) {
		t.Error("5% effect with n=20 must not be significant")
	}
	if !aucSignificant(0.5+effect, 500, 500) {
		t.Error("5% effect with n=500 must be significant")
	}
}

func TestDPrimeAndWelch(t *testing.T) {
	// Zero variance with equal means -> 0; separated constants -> sentinel.
	if got := dPrime([]float64{5, 5, 5}, []float64{5, 5, 5}); got != 0 {
		t.Errorf("identical constants d' = %v, want 0", got)
	}
	if got := dPrime([]float64{1, 1, 1}, []float64{2, 2, 2}); got != sentinelT {
		t.Errorf("separated constants d' = %v, want sentinel %v", got, sentinelT)
	}
	if got := welchT([]float64{1, 1, 1}, []float64{2, 2, 2}); math.Abs(got) != sentinelT {
		t.Errorf("separated constants t = %v, want sentinel", got)
	}
}

func TestRollingMean(t *testing.T) {
	got := rollingMean([]float64{2, 4, 6, 8}, 2)
	want := []float64{2, 3, 5, 7}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rollingMean = %v, want %v", got, want)
		}
	}
}

func TestMeanAndVariance(t *testing.T) {
	x := []float64{2, 4, 4, 4, 5, 5, 7, 9}
	if math.Abs(mean(x)-5) > 1e-12 {
		t.Errorf("mean = %v, want 5", mean(x))
	}
	if math.Abs(sampleVar(x)-4.571428571428571) > 1e-9 {
		t.Errorf("sample variance = %v", sampleVar(x))
	}
}
