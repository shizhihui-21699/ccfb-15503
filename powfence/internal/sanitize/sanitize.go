// Package sanitize turns raw host telemetry into tenant-safe readings.
//
// Pipeline (per tenant, per feature, per aggregation window):
//
//	raw samples
//	  -> temporal aggregation over a fixed window (the primary control;
//	     key-dependent power/frequency excursions are sub-window events)
//	  -> spatial aggregation (all sockets / all CPUs collapse to one scalar;
//	     per-core and per-domain channels are never exposed)
//	  -> bounded-influence residual clipping against a DP baseline
//	  -> Laplace mechanism (epsilon-DP, sensitivity = measured key influence)
//	  -> coarse quantization (post-processing; extra uniform noise)
//	  -> cached snapshot: every poll inside a window gets the identical value,
//	     so an attacker cannot buy independent samples by polling faster
//
// The privacy argument is documented in docs/GUARANTEES.md; the code is
// structured so each stage maps 1:1 to a stage named there.
package sanitize

import (
	"context"
	"errors"
	"sync"
	"time"

	"powfence/internal/dp"
	"powfence/internal/metric"
	"powfence/internal/policy"
	"powfence/internal/ratelimit"
	"powfence/internal/source"
)

// tick is one pre-aggregated sampling tick. Spatial aggregation already
// happened here: energy is summed across every allowed domain, frequency is
// the mean across every logical CPU. No per-core/per-domain identity survives.
type tick struct {
	seq     uint64
	t       time.Time
	energyJ float64 // energy increment over this tick
	freqMHz float64 // mean instantaneous frequency over this tick
}

// Ring is a fixed-size tick history shared by all tenant sanitizers.
// It keeps raw values inside the host process only; tenants can never read
// the ring directly.
type Ring struct {
	mu    sync.RWMutex
	slots []tick
	last  uint64 // sequence number of the most recent tick (0 = empty)
}

// NewRing allocates a ring holding at least capacity ticks.
func NewRing(capacity int) *Ring {
	if capacity < 64 {
		capacity = 64
	}
	return &Ring{
		slots: make([]tick, capacity),
	}
}

// push stores one pre-aggregated tick.
func (r *Ring) push(tk tick) {
	r.mu.Lock()
	r.slots[tk.seq%uint64(len(r.slots))] = tk
	r.last = tk.seq
	r.mu.Unlock()
}

// window returns ticks with timestamps in [start, end), or nil if the ring
// has already overwritten them.
func (r *Ring) window(start, end time.Time) []tick {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.last == 0 {
		return nil
	}
	capN := uint64(len(r.slots))
	// Oldest sequence number still retained. Guard the unsigned subtraction:
	// before the ring fills, seq 1..last are all available.
	var first uint64 = 1
	if r.last >= capN {
		first = r.last - capN + 1
	}
	out := make([]tick, 0, 32)
	for seq := first; seq <= r.last; seq++ {
		tk := r.slots[seq%capN]
		if tk.seq != seq || tk.t.IsZero() {
			continue // slot overwritten before fill or uninitialized
		}
		if !tk.t.Before(start) && tk.t.Before(end) {
			out = append(out, tk)
		}
	}
	return out
}

// Collector polls a Source at a fixed interval and writes pre-aggregated
// ticks into a Ring. One Collector serves all tenants.
type Collector struct {
	src      source.Source
	ring     *Ring
	interval time.Duration

	mu    sync.Mutex
	seq   uint64
	prior map[string]float64
}

// NewCollector wires a source to a ring.
func NewCollector(src source.Source, ring *Ring, tickInterval time.Duration) *Collector {
	return &Collector{
		src:      src,
		ring:     ring,
		interval: tickInterval,
		prior:    map[string]float64{},
	}
}

// Run blocks until ctx is cancelled, polling the source each interval.
func (c *Collector) Run(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.poll(ctx); err != nil {
				// A failed poll is recorded as a gap (no tick), never as a
				// zero-energy tick: a fabricated zero would distort windows.
				continue
			}
		}
	}
}

func (c *Collector) poll(ctx context.Context) error {
	batch, err := c.src.Collect(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.seq++
	seq := c.seq
	now := time.Now()

	// Spatial aggregation of energy: sum allowed domains, using monotonic
	// counter deltas. A discontinuity (wrap we cannot explain, hotplug)
	// causes this tick's energy to be dropped rather than guessed.
	var energy float64
	haveEnergy := false
	for _, rc := range batch.Counters {
		prev, ok := c.prior[rc.Domain]
		c.prior[rc.Domain] = rc.Joules
		if !ok {
			continue
		}
		d := rc.Joules - prev
		if d < 0 {
			// Source already normalizes wraps; a negative delta here means
			// a counter reset. Skip this domain for the tick.
			continue
		}
		energy += d
		haveEnergy = true
	}

	var freqSum float64
	for _, rf := range batch.Frequencies {
		freqSum += rf.MHz
	}
	freq := 0.0
	if len(batch.Frequencies) > 0 {
		freq = freqSum / float64(len(batch.Frequencies))
	}
	c.mu.Unlock()

	tk := tick{seq: seq, t: now, freqMHz: freq}
	if haveEnergy {
		tk.energyJ = energy
	}
	c.ring.push(tk)
	return nil
}

// featureState holds the DP streaming baseline for one feature.
type featureState struct {
	baseline float64 // EMA of previously *released* values (DP post-processing)
	primed   bool
}

// emaAlpha derives the baseline smoothing factor from a fixed 60 s time
// constant: alpha = window/(60s+window), so slow load changes are tracked
// while single-operation excursions average out.
func emaAlpha(windowSec int) float64 {
	w := float64(windowSec)
	return w / (60.0 + w)
}

// Sanitizer is one tenant's stateless-policy, stateful-budget engine. It
// reads pre-aggregated ticks from the shared Ring; the Source lives behind
// the Collector and is never reachable from a tenant path.
type Sanitizer struct {
	pol    *policy.Policy
	ring   *Ring
	rng    dp.Rand
	bucket *ratelimit.Bucket
	ledger *dp.Ledger

	mu          sync.Mutex
	energyState featureState
	freqState   featureState
	cachedStart time.Time
	cached      *metric.Reading
	nominalOnly bool
}

// New builds a tenant sanitizer.
func New(pol *policy.Policy, ring *Ring, rng dp.Rand) *Sanitizer {
	return &Sanitizer{
		pol:         pol,
		ring:        ring,
		rng:         rng,
		bucket:      ratelimit.New(pol.RatePerSecond, pol.Burst),
		ledger:      dp.NewLedger(pol.EpochBudgetEpsilon, pol.EpochSeconds, uint64(time.Now().Unix())),
		nominalOnly: pol.Frequency.Enabled && pol.Frequency.ExposeNominalOnly,
	}
}

// ErrRateLimited / ErrBudgetExhausted are distinguishable denial reasons for
// audit logging.
var (
	ErrRateLimited     = errors.New("rate limit exceeded")
	ErrBudgetExhausted = errors.New("privacy budget exhausted for this epoch")
)

// GetReading serves one tenant request. now is injected for deterministic
// tests; production passes time.Now().
func (s *Sanitizer) GetReading(now time.Time) (*metric.Reading, error) {
	if !s.bucket.Allow(float64(now.UnixNano()) / 1e9) {
		return nil, ErrRateLimited
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Serve the most recent *completed* window. A request at time t returns
	// the window ending at or before t, so a request never observes a
	// partially filled window.
	wd := s.windowDuration()
	wSec := int64(wd.Seconds())
	nowUnix := now.Unix()
	endUnix := nowUnix - nowUnix%wSec
	startUnix := endUnix - wSec
	start := time.Unix(startUnix, 0).UTC()
	end := time.Unix(endUnix, 0).UTC()

	// Fast path: identical request inside the same window. Cached hits spend
	// neither epsilon nor RNG draws, so polling faster cannot buy an
	// attacker independent samples.
	if s.cached != nil && s.cachedStart.Equal(start) {
		return s.cached, nil
	}

	ticks := s.ring.window(start, end)
	if len(ticks) == 0 {
		// First window after startup: no raw data yet. Hand back a static
		// reading (nominal only), spending no budget.
		return s.bootstrapReading(start, end), nil
	}

	r := &metric.Reading{WindowStart: start, WindowEnd: end}
	var epsilon float64

	if s.pol.Energy.Enabled {
		raw := sumEnergy(ticks)
		out, eps, err := s.releaseEnergy(raw)
		if err != nil {
			return nil, err
		}
		epsilon += eps
		r.EnergyJ = &out
		power := out / s.windowDuration().Seconds()
		r.AveragePowerW = &power
	}

	if s.pol.Frequency.Enabled {
		if s.nominalOnly {
			// A constant, policy-defined frequency carries zero information
			// about the current workload: every window returns the same
			// number, so the Hertzbleed-class distinguishing statistic
			// cannot be formed at all.
			nominal := s.pol.Frequency.NominalMHz
			r.FreqMHz = &nominal
			r.NominalMHz = s.pol.Frequency.NominalMHz
			r.MaxMHz = s.pol.Frequency.MaxMHz
		} else {
			raw := meanFreq(ticks)
			out, eps, err := s.releaseFrequency(raw)
			if err != nil {
				return nil, err
			}
			epsilon += eps
			r.FreqMHz = &out
			r.NominalMHz = s.pol.Frequency.NominalMHz
			r.MaxMHz = s.pol.Frequency.MaxMHz
		}
	}

	// Single combined charge: energy and frequency releases within one
	// window compose additively; either both are charged or neither is
	// released, so a budget rejection cannot leak a half-reading.
	if !s.ledger.TryCharge(epsilon, uint64(now.Unix())) {
		return nil, ErrBudgetExhausted
	}
	r.EpsilonSpent = epsilon

	s.cached = r
	s.cachedStart = start
	return r, nil
}

func (s *Sanitizer) windowDuration() time.Duration {
	sec := 1
	if s.pol.Energy.Enabled {
		sec = s.pol.Energy.WindowSeconds
	} else if s.pol.Frequency.Enabled {
		sec = s.pol.Frequency.WindowSeconds
	}
	// Different window lengths are allowed; the effective window is the
	// maximum so each feature still gets >= its configured samples.
	if s.pol.Energy.Enabled && s.pol.Frequency.Enabled &&
		s.pol.Frequency.WindowSeconds > s.pol.Energy.WindowSeconds {
		sec = s.pol.Frequency.WindowSeconds
	}
	return time.Duration(sec) * time.Second
}

func (s *Sanitizer) bootstrapReading(start time.Time, end time.Time) *metric.Reading {
	r := &metric.Reading{WindowStart: start, WindowEnd: end, EpsilonSpent: 0}
	if s.pol.Frequency.Enabled {
		r.NominalMHz = s.pol.Frequency.NominalMHz
		r.MaxMHz = s.pol.Frequency.MaxMHz
		if s.nominalOnly {
			f := s.pol.Frequency.NominalMHz
			r.FreqMHz = &f
		}
	}
	return r
}

// releaseEnergy applies residual clipping, Laplace noise and quantization.
func (s *Sanitizer) releaseEnergy(rawJ float64) (float64, float64, error) {
	cfg := s.pol.Energy
	sensitivity := dp.EnergySensitivityJ(
		string(cfg.DPMode), cfg.SignalMaxDeltaJ, cfg.EnvelopeW, cfg.WindowSeconds)
	scale := dp.LaplaceScale(sensitivity, cfg.ReleaseEpsilon)

	clean := s.clipAndBaseline(&s.energyState, rawJ, cfg.WindowSeconds,
		sensitivity,
		0, cfg.EnvelopeW*float64(cfg.WindowSeconds),
		cfg.DPMode == policy.DPModeFullRange)

	noisy := clean + dp.Laplace(s.rng, scale)
	out := dp.Quantize(noisy, cfg.QuantizeJ)
	if out < 0 {
		out = 0 // energy is non-negative; this is post-processing of a DP value
	}
	return out, cfg.ReleaseEpsilon, nil
}

func (s *Sanitizer) releaseFrequency(rawMHz float64) (float64, float64, error) {
	cfg := s.pol.Frequency
	sensitivity := dp.FrequencySensitivityMHz(
		string(cfg.DPMode), cfg.SignalMaxDeltaMHz, cfg.EnvelopeMHz)
	scale := dp.LaplaceScale(sensitivity, cfg.ReleaseEpsilon)

	clean := s.clipAndBaseline(&s.freqState, rawMHz, cfg.WindowSeconds,
		sensitivity,
		0, cfg.EnvelopeMHz,
		cfg.DPMode == policy.DPModeFullRange)

	noisy := clean + dp.Laplace(s.rng, scale)
	out := dp.Quantize(noisy, cfg.QuantizeMHz)
	if out < 0 {
		out = 0
	}
	if cfg.MaxMHz > 0 && out > cfg.MaxMHz {
		out = cfg.MaxMHz
	}
	return out, cfg.ReleaseEpsilon, nil
}

// clipAndBaseline implements the bounded-influence model:
//
//	clean = baseline + clip(x - baseline, [-s, +s])
//
// baseline is an EMA of past released (already DP) values, hence independent
// of the current window's secret. s is the sensitivity, so the current
// secret's only influence on clean is bounded by s in absolute value.
//
// In full-range mode the baseline is unused and the raw value is clipped to
// the physical envelope instead.
func (s *Sanitizer) clipAndBaseline(st *featureState, x float64, windowSec int,
	sensitivity, lo, hi float64, fullRange bool) float64 {
	if fullRange {
		return dp.Clip(x, lo, hi)
	}
	if !st.primed {
		// First observation seeds the baseline from raw data. This happens
		// exactly once per tenant/feature and is documented in the threat
		// model as initialization outside the protected workload.
		st.baseline = x
		st.primed = true
		return x
	}
	residual := dp.Clip(x-st.baseline, -sensitivity, sensitivity)
	clean := st.baseline + residual

	// Baseline tracks *released* values, so it is DP post-processing and
	// adds no fresh dependence on secrets.
	alpha := emaAlpha(windowSec)
	st.baseline = (1-alpha)*st.baseline + alpha*clean
	return clean
}

func sumEnergy(ticks []tick) float64 {
	var sum float64
	for _, t := range ticks {
		sum += t.energyJ
	}
	return sum
}

func meanFreq(ticks []tick) float64 {
	var sum float64
	var n int
	for _, t := range ticks {
		if t.freqMHz > 0 {
			sum += t.freqMHz
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}
