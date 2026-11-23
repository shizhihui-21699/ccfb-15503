// Package dp implements the differential-privacy layer: the Laplace
// mechanism, sensitivity selection and epsilon accounting.
//
// All randomness goes through a Rand interface so tests and the self-test
// simulator are fully reproducible. Production seeds a ChaCha8 source from
// crypto/rand.
package dp

import (
	cryptorand "crypto/rand"
	"math"
	"math/rand/v2"
)

// Rand is the randomness contract used by every mechanism.
type Rand interface {
	// Float64 returns a uniformly distributed value in [0,1).
	Float64() float64
}

// NewSecureRand seeds a ChaCha8-based PRNG from the kernel CSPRNG.
// ChaCha8 is the default source in math/rand/v2 and is not predictable by an
// in-guest attacker, which is the requirement for the noise to be private.
func NewSecureRand() (*rand.Rand, error) {
	var seed [32]byte
	if _, err := cryptorand.Read(seed[:]); err != nil {
		return nil, err
	}
	return rand.New(rand.NewChaCha8(seed)), nil
}

// Laplace draws one sample from Laplace(0, b).
//
// Inverse-CDF sampling: X = -b * sign(U) * ln(1 - |U|) with U uniform on
// (-1,1). Implemented via the standard uniform V in (0,1):
//
//	X = b * ln(V) with probability 1/2, else -b * ln(V).
//
// V is clamped away from 0 and 1 so the transform is finite.
func Laplace(r Rand, b float64) float64 {
	v := r.Float64()
	const eps = 1e-12
	if v < eps {
		v = eps
	} else if v > 1-eps {
		v = 1 - eps
	}
	mag := b * math.Log(v) // ln(v) <= 0
	if r.Float64() < 0.5 {
		return mag
	}
	return -mag
}

// LaplaceScale returns the Laplace scale b = sensitivity / epsilon.
func LaplaceScale(sensitivity, epsilon float64) float64 {
	if epsilon <= 0 || sensitivity <= 0 {
		// Misconfiguration must fail loud rather than produce zero noise.
		panic("dp: sensitivity and epsilon must be positive")
	}
	return sensitivity / epsilon
}

// EnergySensitivityJ returns the Laplace sensitivity for one released
// energy increment (joules) over a window of windowSec seconds.
//
// signalBounded: the measured maximum key-induced change within one window.
// fullRange:     the physical envelope (package power limit * window).
func EnergySensitivityJ(mode string, signalMaxDeltaJ, envelopeW float64, windowSec int) float64 {
	switch mode {
	case "full_range":
		return envelopeW * float64(windowSec)
	default: // signal_bounded
		return signalMaxDeltaJ
	}
}

// FrequencySensitivityMHz is the frequency analogue.
func FrequencySensitivityMHz(mode string, signalMaxDeltaMHz, envelopeMHz float64) float64 {
	switch mode {
	case "full_range":
		return envelopeMHz
	default:
		return signalMaxDeltaMHz
	}
}

// Quantize rounds x to the nearest multiple of step. Step <= 0 is a no-op.
//
// Quantization after noise preserves the DP guarantee: post-processing of a
// DP output cannot increase privacy loss. It additionally contributes an
// independent uniform(-step/2, step/2) rounding error that the empirical
// self-test counts as extra attacker noise.
func Quantize(x, step float64) float64 {
	if step <= 0 {
		return x
	}
	return math.Round(x/step) * step
}

// Clip forces x into [lo, hi].
func Clip(x, lo, hi float64) float64 {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

// Ledger tracks sequential composition of epsilon over a rolling epoch.
//
// Sequential composition: for mechanisms M1..Mk with epsilons e1..ek, the
// composition is (sum ei)-DP. The ledger refuses releases that would exceed
// the epoch budget; epoch rollover zeroes the counter.
type Ledger struct {
	budget   float64
	spent    float64
	epochEnd uint64 // unix seconds
	epochLen int
}

// NewLedger creates a ledger with the given per-epoch epsilon budget.
func NewLedger(budget float64, epochLenSec int, nowUnix uint64) *Ledger {
	return &Ledger{
		budget:   budget,
		epochLen: epochLenSec,
		epochEnd: nowUnix + uint64(epochLenSec),
	}
}

// TryCharge charges epsilon if the epoch budget allows it. Rollover first.
// Returns false when the release must be denied.
func (l *Ledger) TryCharge(epsilon float64, nowUnix uint64) bool {
	if nowUnix >= l.epochEnd {
		l.spent = 0
		l.epochEnd = nowUnix + uint64(l.epochLen)
	}
	if l.spent+epsilon > l.budget {
		return false
	}
	l.spent += epsilon
	return true
}

// Spent reports epsilon already consumed in the current epoch.
func (l *Ledger) Spent() float64 { return l.spent }

// Budget reports the configured epoch budget.
func (l *Ledger) Budget() float64 { return l.budget }

// SeedFromBytes is a test helper that turns 32 bytes into a deterministic
// ChaCha8 seed source.
func SeedFromBytes(seed [32]byte) *rand.Rand {
	return rand.New(rand.NewChaCha8(seed))
}
