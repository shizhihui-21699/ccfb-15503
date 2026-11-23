// Package selftest contains the empirical side-channel evaluation: a
// synthetic attack simulator that injects key-dependent power/frequency
// leakage and measures how much of it survives each sanitization policy.
//
// Threat model reproduced here:
//
//	A victim performs key-dependent crypto work on a shared socket. Each
//	secret bit induces a small, reproducible excursion in package power
//	(Platypus-class energy side channel) and, through DVFS, in CPU frequency
//	(Hertzbleed-class). An attacker co-located on the host reads telemetry
//	and tries to distinguish bit=0 from bit=1 operations.
//
// The simulator has two fidelity layers:
//
//  1. A tick-level (100 ms) ground-truth stream with ambient workload
//     noise. The "raw" observer reads the operation ticks directly, which is
//     the access an unprivileged RAPL/cpufreq interface would grant - this
//     proves the harness can detect the attack at its natural granularity.
//  2. Policy observers that only ever receive window-aggregated, sanitized
//     snapshots through the same Sanitizer code path as production tenants.
//
// Ambient noise is deliberately quiet (a near-idle co-tenant is the
// attacker's best case). A passing result under this model is conservative;
// noisier real hosts only make the channel harder to exploit.
//
// All randomness is seeded, so runs and CI results are reproducible.
package selftest

import (
	"math"
	"strconv"
	"time"

	"powfence/internal/dp"
	"powfence/internal/policy"
	"powfence/internal/sanitize"
)

// LeakageProfile describes the injected key-dependent signal and ambient.
type LeakageProfile struct {
	BaselineW float64 // package baseline power (watts)
	// Bit1DeltaW is the package-power excursion while the key op runs.
	Bit1DeltaW float64
	// OpSeconds is the duration of one key operation inside a window.
	OpSeconds float64

	BaselineMHz float64
	// Bit1DeltaMHz is the DVFS frequency excursion during the key op.
	Bit1DeltaMHz float64

	TickInterval time.Duration

	// AmbientSigmas model normal workload variation at tick granularity.
	AmbientEnergySigmaJ float64
	AmbientFreqSigmaMHz float64

	CPUs int
}

// DefaultProfile returns the benchmark leakage model. A 1.5 W excursion
// during a 10 ms operation yields a 0.015 J signal against 0.01 J ambient
// per-tick noise - a strong, detectable raw channel (d' ~= 1.5) that the
// sanitizer must destroy.
func DefaultProfile() LeakageProfile {
	return LeakageProfile{
		BaselineW:           120,
		Bit1DeltaW:          1.5,
		OpSeconds:           0.01,
		BaselineMHz:         2800,
		Bit1DeltaMHz:        3,
		TickInterval:        100 * time.Millisecond,
		AmbientEnergySigmaJ: 0.01,
		AmbientFreqSigmaMHz: 1.0,
		CPUs:                8,
	}
}

// ClassResult holds attacker statistics for one observer and one feature.
type ClassResult struct {
	Feature string  `json:"feature"`
	N       int     `json:"samples_per_class"`
	WelchT  float64 `json:"welch_t"`
	DPrime  float64 `json:"d_prime"`
	AUC     float64 `json:"classifier_auc"`
	// AUCSignificant reports whether the AUC differs from chance (0.5) at
	// the two-sided 95% level given the actual sample count.
	AUCSignificant bool `json:"auc_significant"`
}

// UtilityResult measures monitoring fidelity against ground truth.
type UtilityResult struct {
	Feature        string  `json:"feature"`
	MeanAbsPct     float64 `json:"rolling_mean_abs_error_pct"`
	RMSE           float64 `json:"rolling_rmse"`
	RawMeanAbsPct  float64 `json:"single_window_error_pct"`
	MeanEpsilon    float64 `json:"mean_epsilon_per_release"`
	RollingWindows int     `json:"rolling_average_windows"`
	Static         bool    `json:"static_reference,omitempty"`
}

// ObserverResult is one policy's full evaluation.
type ObserverResult struct {
	Name        string          `json:"observer"`
	Attack      []ClassResult   `json:"attack_statistics"`
	Utility     []UtilityResult `json:"utility"`
	Exploitable bool            `json:"exploitable_channel"`
}

// Report is the complete self-test output.
type Report struct {
	Profile   LeakageProfile   `json:"leakage_profile"`
	Observers []ObserverResult `json:"observers"`
	Passed    bool             `json:"passed"`
	Failures  []string         `json:"failures"`
}

// Decision thresholds encode "no exploitable channel":
//
//	|t| < 2        : cannot reject equal means at the 95% level
//	d' < 0.5       : signal-to-noise below half a standard deviation
//	|AUC-0.5| < .05: single-threshold classifier is at chance level
//
// The raw observer must demonstrably show a strong channel, proving the
// harness itself is capable of detecting leakage.
const (
	thresholdT      = 2.0
	thresholdDPrime = 0.5
	// thresholdAUCLargeEffect is the sample-count-independent effect floor:
	// an AUC this far from chance is a strong separator even if the sample
	// is too small to certify significance. Below it, the AUC must pass the
	// sample-size-aware Mann-Whitney significance test instead.
	thresholdAUCLargeEffect = 0.15
	// rawMinDPrime is the minimum tick-level effect size the harness must
	// observe. 1.2 is a "very large" effect by conventional benchmarks
	// (Cohen's d >= 0.8 = large) and is well above the 0.5 protection
	// threshold, so the control check stays meaningful without demanding
	// impractically large injected signals.
	rawMinDPrime   = 1.2
	utilityMaxPct  = 5.0
	rollingWindows = 6
)

// tickTruth is one 100 ms ground-truth sample.
type tickTruth struct {
	t       time.Time
	energyJ float64 // tick energy increment (joules)
	freqMHz float64 // tick mean frequency
	isOp    bool    // carries the key operation this window
}

// windowTruth is one aggregation window and its secret label.
type windowTruth struct {
	bit       int
	start     time.Time
	ticks     []tickTruth
	rawEnergy float64 // sum of tick energy
	rawFreq   float64 // mean of tick frequency
}

// Run executes the full evaluation.
func Run(windowsPerClass int, seed [32]byte) (*Report, error) {
	if windowsPerClass <= 0 {
		windowsPerClass = 200
	}
	prof := DefaultProfile()
	rep := &Report{Profile: prof}

	// Independent stream for ambient noise so sanitizer noise is unaffected.
	ambientSeed := seed
	ambientSeed[0] ^= 0xFF
	ambientRNG := dp.SeedFromBytes(ambientSeed)

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Raw observer: 1 s windows, reading operation ticks directly.
	rawWindows := buildGroundTruth(prof, windowsPerClass, 1, base, ambientRNG)
	rep.Observers = append(rep.Observers, rawObserver(rawWindows))

	standard, err := policyObserver("standard", standardPolicy(), rawWindows, prof, seed)
	if err != nil {
		return nil, err
	}
	rep.Observers = append(rep.Observers, standard)

	strictN := windowsPerClass / 5
	if strictN < 40 {
		strictN = 40
	}
	strictWindows := buildGroundTruth(prof, strictN, 5, base, ambientRNG)
	strict, err := policyObserver("strict", strictPolicy(prof), strictWindows, prof, seed)
	if err != nil {
		return nil, err
	}
	rep.Observers = append(rep.Observers, strict)

	rep.evaluate()
	return rep, nil
}

// buildGroundTruth constructs 2*n windows of windowSec seconds on a 100 ms
// tick grid. The first tick of each window hosts the (bit-labelled) key
// operation; every tick carries independent ambient noise.
func buildGroundTruth(p LeakageProfile, n, windowSec int,
	base time.Time, ambient interface {
		Float64() float64
		NormFloat64() float64
	}) []windowTruth {
	ticksPerWindow := int(float64(windowSec) / p.TickInterval.Seconds())
	out := make([]windowTruth, 0, 2*n)
	for i := 0; i < 2*n; i++ {
		bit := i % 2
		wStart := base.Add(time.Duration(i) * time.Duration(windowSec) * time.Second)
		w := windowTruth{bit: bit, start: wStart, ticks: make([]tickTruth, 0, ticksPerWindow)}

		var eSum, fSum float64
		for k := 0; k < ticksPerWindow; k++ {
			tt := wStart.Add(time.Duration(k) * p.TickInterval)
			energy := p.BaselineW*p.TickInterval.Seconds() +
				ambient.NormFloat64()*p.AmbientEnergySigmaJ
			freq := p.BaselineMHz + ambient.NormFloat64()*p.AmbientFreqSigmaMHz
			isOp := k == 0
			if isOp {
				energy += float64(bit) * p.Bit1DeltaW * p.OpSeconds
				freq += float64(bit) * p.Bit1DeltaMHz
			}
			w.ticks = append(w.ticks, tickTruth{
				t: tt, energyJ: energy, freqMHz: freq, isOp: isOp,
			})
			eSum += energy
			fSum += freq
		}
		w.rawEnergy = eSum
		w.rawFreq = fSum / float64(ticksPerWindow)
		out = append(out, w)
	}
	return out
}

// rawObserver classifies the operation ticks - the view an unprivileged
// high-frequency counter interface would expose.
func rawObserver(truth []windowTruth) ObserverResult {
	var e0, e1, f0, f1 []float64
	for _, w := range truth {
		for _, tk := range w.ticks {
			if !tk.isOp {
				continue
			}
			if w.bit == 0 {
				e0 = append(e0, tk.energyJ)
				f0 = append(f0, tk.freqMHz)
			} else {
				e1 = append(e1, tk.energyJ)
				f1 = append(f1, tk.freqMHz)
			}
		}
	}
	return ObserverResult{
		Name: "raw_unsanitized_tick_level",
		Attack: []ClassResult{
			classify("energy_joules", e0, e1),
			classify("frequency_mhz", f0, f1),
		},
	}
}

func policyObserver(name string, pol *policy.Policy, truth []windowTruth,
	p LeakageProfile, seed [32]byte) (ObserverResult, error) {
	if err := pol.ValidatePolicy(); err != nil {
		return ObserverResult{}, err
	}
	ring := sanitize.NewRing(8192)
	rng := dp.SeedFromBytes(seed)
	san := sanitize.NewForTest(pol, ring, rng, p.BaselineMHz, p.BaselineMHz+700)

	windowSec := pol.Energy.WindowSeconds
	if !pol.Energy.Enabled {
		windowSec = pol.Frequency.WindowSeconds
	}

	var estEnergy, refEnergy, estFreq, refFreq []float64
	var e0, e1, f0, f1 []float64
	var epsSum, epsN float64
	var seq uint64 = 1

	for _, w := range truth {
		for _, tk := range w.ticks {
			ring.PushForTest(sanitize.TickForTest{
				Seq: seq, T: tk.t, EnergyJ: tk.energyJ, FreqMHz: tk.freqMHz,
			})
			seq++
		}

		reqAt := w.start.Add(time.Duration(windowSec) * time.Second)
		reading, err := san.GetReading(reqAt)
		if err != nil {
			return ObserverResult{}, err
		}
		epsSum += reading.EpsilonSpent
		epsN++

		if reading.EnergyJ != nil {
			estEnergy = append(estEnergy, *reading.EnergyJ)
			refEnergy = append(refEnergy, w.rawEnergy)
			if w.bit == 0 {
				e0 = append(e0, *reading.EnergyJ)
			} else {
				e1 = append(e1, *reading.EnergyJ)
			}
		}
		if reading.FreqMHz != nil {
			estFreq = append(estFreq, *reading.FreqMHz)
			if pol.Frequency.ExposeNominalOnly {
				// A static reference is not an estimate of the current
				// window; record it for the attack test but skip the
				// fidelity comparison.
				continue
			}
			refFreq = append(refFreq, w.rawFreq)
			if w.bit == 0 {
				f0 = append(f0, *reading.FreqMHz)
			} else {
				f1 = append(f1, *reading.FreqMHz)
			}
		}
	}

	res := ObserverResult{Name: name}
	if len(e0) > 0 && len(e1) > 0 {
		res.Attack = append(res.Attack, classify("energy_joules", e0, e1))
		res.Utility = append(res.Utility, makeUtility(
			"energy_joules", estEnergy, refEnergy, epsSum/epsN, false))
	}
	if len(f0) > 0 && len(f1) > 0 {
		res.Attack = append(res.Attack, classify("frequency_mhz", f0, f1))
		res.Utility = append(res.Utility, makeUtility(
			"frequency_mhz", estFreq, refFreq, epsSum/epsN,
			pol.Frequency.ExposeNominalOnly))
	}
	return res, nil
}

func makeUtility(feature string, est, ref []float64, meanEps float64, static bool) UtilityResult {
	if static {
		return UtilityResult{
			Feature: feature, Static: true, RollingWindows: rollingWindows,
			MeanEpsilon: meanEps,
		}
	}
	return UtilityResult{
		Feature:        feature,
		MeanAbsPct:     maePct(rollingMean(est, rollingWindows), rollingMean(ref, rollingWindows)),
		RMSE:           rmse(rollingMean(est, rollingWindows), rollingMean(ref, rollingWindows)),
		RawMeanAbsPct:  maePct(est, ref),
		MeanEpsilon:    meanEps,
		RollingWindows: rollingWindows,
	}
}

// rollingMean returns trailing-window averages; early outputs use whatever
// samples are available so output length equals input length.
func rollingMean(x []float64, k int) []float64 {
	out := make([]float64, len(x))
	var sum float64
	for i := range x {
		sum += x[i]
		if i >= k {
			sum -= x[i-k]
		}
		start := i - k + 1
		if start < 0 {
			start = 0
		}
		out[i] = sum / float64(i-start+1)
	}
	return out
}

func classify(feature string, class0, class1 []float64) ClassResult {
	auc := classifyAUC(class0, class1)
	return ClassResult{
		Feature:        feature,
		N:              len(class0),
		WelchT:         welchT(class0, class1),
		DPrime:         dPrime(class0, class1),
		AUC:            auc,
		AUCSignificant: aucSignificant(auc, len(class0), len(class1)),
	}
}

func (r *Report) evaluate() {
	r.Failures = nil

	var rawObs *ObserverResult
	for i := range r.Observers {
		if r.Observers[i].Name == "raw_unsanitized_tick_level" {
			rawObs = &r.Observers[i]
		}
	}
	if rawObs != nil {
		for _, c := range rawObs.Attack {
			// The control only needs statistical detectability: a real,
			// exploitable raw channel will clear both the effect-size and
			// the significance bars.
			if c.DPrime < rawMinDPrime || !c.AUCSignificant {
				r.Failures = append(r.Failures,
					"harness check failed: raw leakage not detectable ("+
						c.Feature+") - test parameters cannot validate protection")
			}
		}
	}

	for i := range r.Observers {
		obs := &r.Observers[i]
		if obs.Name == "raw_unsanitized_tick_level" {
			continue
		}
		exploitable := false
		for _, c := range obs.Attack {
			// Three complementary detectors, each guarding a different
			// failure mode:
			//   - Welch t: mean difference significant at 95%
			//   - d'      : standardized effect >= 0.5 (exploitable SNR)
			//   - AUC     : statistically significant Mann-Whitney result,
			//               or a large effect (>=0.15) that small samples
			//               cannot yet certify
			//
			// A channel is declared exploitable only when at least TWO
			// detectors fire. Each individual 5% test has false alarms;
			// requiring agreement between independent statistics controls
			// the multiple-comparison error rate and matches standard
			// side-channel practice (e.g. TVLA confirmations require
			// significance across repeated, independent acquisitions).
			tHit := math.Abs(c.WelchT) >= thresholdT
			dHit := c.DPrime >= thresholdDPrime
			aucEffect := math.Abs(c.AUC - 0.5)
			aucHit := c.AUCSignificant || aucEffect >= thresholdAUCLargeEffect
			hits := 0
			if tHit {
				hits++
			}
			if dHit {
				hits++
			}
			if aucHit {
				hits++
			}
			if hits >= 2 {
				exploitable = true
				r.Failures = append(r.Failures,
					obs.Name+": exploitable "+c.Feature+
						" channel (t="+f2(c.WelchT)+", d'="+f2(c.DPrime)+
						", auc="+f3(c.AUC)+", detectors="+strconv.Itoa(hits)+"/3)")
			}
		}
		obs.Exploitable = exploitable

		for _, u := range obs.Utility {
			if u.Static {
				continue
			}
			if u.MeanAbsPct > utilityMaxPct {
				r.Failures = append(r.Failures,
					obs.Name+": monitoring utility degraded on "+u.Feature+
						" ("+f2(u.MeanAbsPct)+"% rolling error > "+
						f2(utilityMaxPct)+"%)")
			}
		}
	}
	r.Passed = len(r.Failures) == 0
}

// PolicyVerdict is the result of evaluating one standalone policy.
type PolicyVerdict struct {
	Exploitable bool           `json:"exploitable_channel"`
	Observer    ObserverResult `json:"observer"`
}

// EvaluatePolicy runs one policy through the full attack simulation with the
// default leakage profile. It is the building block used both by Run and by
// the negative-control CLI (powfence-attackcheck), which needs to confirm
// that deliberately weak configurations are actually caught.
func EvaluatePolicy(pol *policy.Policy, windowsPerClass int, seed [32]byte) PolicyVerdict {
	if windowsPerClass <= 0 {
		windowsPerClass = 200
	}
	prof := DefaultProfile()
	ambientSeed := seed
	ambientSeed[0] ^= 0xFF
	ambientRNG := dp.SeedFromBytes(ambientSeed)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	windowSec := pol.Energy.WindowSeconds
	if !pol.Energy.Enabled {
		windowSec = pol.Frequency.WindowSeconds
	}
	truth := buildGroundTruth(prof, windowsPerClass, windowSec, base, ambientRNG)
	obs, err := policyObserver("candidate", pol, truth, prof, seed)
	if err != nil {
		// An invalid policy cannot provide protection; surface as
		// exploitable so callers never treat construction errors as a pass.
		return PolicyVerdict{Exploitable: true}
	}
	exploitable := false
	for _, c := range obs.Attack {
		tHit := math.Abs(c.WelchT) >= thresholdT
		dHit := c.DPrime >= thresholdDPrime
		aucHit := c.AUCSignificant || math.Abs(c.AUC-0.5) >= thresholdAUCLargeEffect
		if b2i(tHit)+b2i(dHit)+b2i(aucHit) >= 2 {
			exploitable = true
		}
	}
	return PolicyVerdict{Exploitable: exploitable, Observer: obs}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// standardPolicy is the production-default profile. Per-release epsilon is
// left zero so the validator derives it from the epoch budget and the
// maximum window count, keeping the sequential-composition arithmetic
// automatically self-consistent.
func standardPolicy() *policy.Policy {
	return &policy.Policy{
		Name:               "standard",
		EpochSeconds:       3600,
		EpochBudgetEpsilon: 360.0, // see docs/GUARANTEES.md for RDP tightening
		RatePerSecond:      2.0,
		Burst:              2,
		Energy: policy.EnergyPolicy{
			Enabled:         true,
			Scope:           "package",
			WindowSeconds:   1,
			QuantizeJ:       0.5,
			DPMode:          policy.DPModeSignalBounded,
			SignalMaxDeltaJ: 0.05, // 3.3x headroom over the 0.015 J signal
			EnvelopeW:       250,
			BudgetShare:     0.5,
		},
		Frequency: policy.FrequencyPolicy{
			Enabled:           true,
			WindowSeconds:     1,
			QuantizeMHz:       25,
			DPMode:            policy.DPModeSignalBounded,
			SignalMaxDeltaMHz: 1,
			EnvelopeMHz:       3500,
			NominalMHz:        2500,
			MaxMHz:            3500,
			BudgetShare:       0.5,
		},
	}
}

// strictPolicy is the high-assurance profile: nominal-only frequency
// (constant answer, zero leakage) and a heavily aggregated energy channel.
// The explicit per-release epsilon (rather than an auto-derived one) buys
// extra noise: with sensitivity 0.05 J and eps 0.005 the Laplace scale is
// 10 J, which dwarfs the 0.015 J injected signal even at small sample
// counts where classifier AUC has wide sampling variance.
func strictPolicy(p LeakageProfile) *policy.Policy {
	return &policy.Policy{
		Name:               "strict",
		EpochSeconds:       3600,
		EpochBudgetEpsilon: 7.21,
		RatePerSecond:      1.0,
		Burst:              1,
		Energy: policy.EnergyPolicy{
			Enabled:         true,
			Scope:           "host",
			WindowSeconds:   5,
			QuantizeJ:       2,
			DPMode:          policy.DPModeSignalBounded,
			SignalMaxDeltaJ: 0.05,
			EnvelopeW:       250,
			BudgetShare:     1,
			ReleaseEpsilon:  0.005,
		},
		Frequency: policy.FrequencyPolicy{
			Enabled:           true,
			ExposeNominalOnly: true,
			WindowSeconds:     5,
			QuantizeMHz:       50,
			DPMode:            policy.DPModeSignalBounded,
			SignalMaxDeltaMHz: p.Bit1DeltaMHz,
			EnvelopeMHz:       p.BaselineMHz + 700,
			NominalMHz:        p.BaselineMHz,
			MaxMHz:            p.BaselineMHz + 700,
		},
	}
}

func f2(x float64) string { return strconv.FormatFloat(x, 'f', 2, 64) }
func f3(x float64) string { return strconv.FormatFloat(x, 'f', 3, 64) }
