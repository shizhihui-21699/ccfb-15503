// Package policy defines the tenant-facing sanitization policy and the
// validation logic that turns a human-edited JSON policy into a fully
// resolved, internally consistent one.
//
// Every security-relevant knob of the proxy lives here. The sanitizer
// (internal/sanitize) and the privacy accounting (internal/dp) are pure
// functions of a Policy, which makes the guarantees auditable: there is no
// per-request code path that can silently weaken protection.
package policy

import (
	"errors"
	"fmt"
	"math"
)

// DPMode selects the sensitivity used by the Laplace mechanism.
type DPMode string

const (
	// DPModeSignalBounded is the primary guarantee.
	//
	// Sensitivity is the per-release change that the protected secret can
	// induce in the reported statistic (SignalMaxDeltaJ / SignalMaxDeltaMHz),
	// measured on the target hardware and enforced at runtime by clipping.
	// Under the bounded-influence adjacency definition ("neighbouring
	// workloads differ only in the key material of one cryptographic
	// operation"), this yields classic epsilon-DP with an explicit, small
	// sensitivity and therefore usable noise.
	DPModeSignalBounded DPMode = "signal_bounded"

	// DPModeFullRange is the conservative, model-free profile.
	//
	// Sensitivity is the full physical envelope of the counter (max energy /
	// max frequency over one window). The resulting epsilon-DP statement is
	// unconditional on any hardware characterization, but the noise scale is
	// usually too large for useful monitoring. It exists for operators who
	// want a guarantee that does not rest on a measured signal bound.
	DPModeFullRange DPMode = "full_range"
)

// EnergyPolicy controls how RAPL-style energy counters are released.
type EnergyPolicy struct {
	// Enabled turns energy telemetry on for tenants on this policy.
	Enabled bool `json:"enabled"`

	// Scope is the aggregation scope exposed to the tenant:
	// "package" (whole socket, PP0/PP1/DRAM/PSys domains merged) or
	// "host"    (all sockets merged into one number).
	// Per-core and per-domain counters are never exposed because they carry
	// the strongest single-operation signal.
	Scope string `json:"scope"`

	// WindowSeconds is the minimum aggregation interval. Every tenant read
	// returns the value of the most recent completed window; sub-window
	// polling always hits the same cached snapshot (see sanitize.Snapshot).
	WindowSeconds int `json:"window_seconds"`

	// QuantizeJ rounds released energy increments to whole multiples of this
	// many joules. Set to 0 to disable quantization (not recommended).
	QuantizeJ float64 `json:"quantize_joules"`

	// DPMode selects the Laplace sensitivity (see DPMode constants).
	DPMode DPMode `json:"dp_mode"`

	// ReleaseEpsilon is the epsilon spent per released window snapshot.
	// If 0, it is derived from EpochBudgetEpsilon / max releases per epoch.
	ReleaseEpsilon float64 `json:"release_epsilon,omitempty"`

	// SignalMaxDeltaJ is the maximum absolute change, in joules, that the
	// protected secret (one key-dependent operation) can cause in a single
	// window's energy increment on this hardware. Required for
	// signal_bounded mode; populated from hardware characterization (see
	// docs/CHARACTERIZATION.md).
	SignalMaxDeltaJ float64 `json:"signal_max_delta_joules,omitempty"`

	// EnvelopeW is the maximum sustained package power (watts) the clipping
	// stage is willing to accept. Used both as the full-range sensitivity
	// basis and as an anti-spike clip. A safe default is the package TDP.
	EnvelopeW float64 `json:"envelope_watts"`

	// BudgetShare is the fraction of EpochBudgetEpsilon allocated to this
	// feature. When both energy and frequency are enabled, shares must sum
	// to <= 1 so the sequential composition of every released window stays
	// within the advertised epoch budget. Defaults to an equal split.
	BudgetShare float64 `json:"budget_share,omitempty"`
}

// FrequencyPolicy controls how CPU frequency information is released.
type FrequencyPolicy struct {
	Enabled bool `json:"enabled"`

	// WindowSeconds behaves like EnergyPolicy.WindowSeconds.
	WindowSeconds int `json:"window_seconds"`

	// ExposeNominalOnly drops frequency telemetry entirely and reports the
	// static nominal/maximum frequencies from CPUID. This is the
	// high-assurance setting: Hertzbleed's distinguishing statistic is the
	// time-varying frequency, which a constant answer cannot leak.
	ExposeNominalOnly bool `json:"expose_nominal_only"`

	// QuantizeMHz rounds released frequencies to multiples of this value.
	QuantizeMHz float64 `json:"quantize_mhz"`

	DPMode DPMode `json:"dp_mode"`

	ReleaseEpsilon float64 `json:"release_epsilon,omitempty"`

	// SignalMaxDeltaMHz bounds the key-induced frequency excursion within
	// one window (Hertzbleed-class excursions are a few MHz at most).
	SignalMaxDeltaMHz float64 `json:"signal_max_delta_mhz,omitempty"`

	// EnvelopeMHz is the CPU maximum frequency; full-range sensitivity basis.
	EnvelopeMHz float64 `json:"envelope_mhz"`

	// NominalMHz and MaxMHz are the static values returned in
	// ExposeNominalOnly mode.
	NominalMHz float64 `json:"nominal_mhz"`
	MaxMHz     float64 `json:"max_mhz"`

	// BudgetShare behaves like EnergyPolicy.BudgetShare. A nominal-only
	// frequency policy spends no budget and needs no share.
	BudgetShare float64 `json:"budget_share,omitempty"`
}

// Policy is the resolved per-tenant sanitization policy.
type Policy struct {
	Name string `json:"name"`

	// EpochSeconds is the rolling privacy-budget epoch length.
	EpochSeconds int `json:"epoch_seconds"`
	// EpochBudgetEpsilon caps the sum of per-release epsilons one tenant may
	// consume within one epoch.
	EpochBudgetEpsilon float64 `json:"epoch_budget_epsilon"`

	// RatePerSecond is the maximum number of API responses per tenant per
	// second. Responses served from the same cached snapshot still count
	// toward the rate limit, but spend no additional privacy budget.
	RatePerSecond float64 `json:"rate_per_second"`
	// Burst is the token-bucket burst allowance.
	Burst int `json:"burst"`

	Energy    EnergyPolicy    `json:"energy"`
	Frequency FrequencyPolicy `json:"frequency"`
}

// Config is the on-disk configuration: transport, tenants and their policies.
type Config struct {
	Listen struct {
		// Transport: "unix" (default), "tcp", or "vsock" (Linux only).
		Transport string `json:"transport"`
		// Address semantics depend on transport:
		//   unix  -> socket path, e.g. /run/powfence/powfence.sock
		//   tcp   -> 127.0.0.1:9100
		//   vsock -> "<context-id>:<port>", use context id 0 for host
		Address string `json:"address"`
	} `json:"listen"`

	// Source selects the metric backend: "rapl" (Linux hardware) or
	// "mock" (deterministic synthetic source, used for tests and demos).
	Source string `json:"source"`

	// AuditPath receives one JSON line per released snapshot / denied
	// request. Empty disables audit logging.
	AuditPath string `json:"audit_path"`

	// Policies maps policy name -> policy.
	Policies map[string]*Policy `json:"policies"`

	// Tenants maps bearer token -> tenant entry. Tokens are deployment
	// secrets; keep the file mode 0600.
	Tenants map[string]Tenant `json:"tenants"`
}

// Tenant binds an authentication token to a policy.
type Tenant struct {
	Policy string `json:"policy"`
	// Label is a non-secret identifier used in audit logs.
	Label string `json:"label"`
}

func positive(x float64) bool { return !math.IsNaN(x) && !math.IsInf(x, 0) && x > 0 }

// ValidatePolicy validates a single standalone policy (used by the self-test
// harness, which builds policies without a full Config).
func (p *Policy) ValidatePolicy() error { return p.validate() }

// Validate checks a Config and resolves derived fields. The returned Config
// is the one the daemon must use; the input is not mutated.
func (c *Config) Validate() error {
	if c.Source == "" {
		c.Source = "rapl"
	}
	switch c.Source {
	case "rapl", "mock":
	default:
		return fmt.Errorf("unknown source %q (want rapl|mock)", c.Source)
	}
	if c.Listen.Transport == "" {
		c.Listen.Transport = "unix"
	}
	switch c.Listen.Transport {
	case "unix", "tcp", "vsock":
	default:
		return fmt.Errorf("unknown transport %q", c.Listen.Transport)
	}
	if len(c.Policies) == 0 {
		return errors.New("no policies defined")
	}
	if len(c.Tenants) == 0 {
		return errors.New("no tenants defined")
	}
	for name, p := range c.Policies {
		if err := p.validate(); err != nil {
			return fmt.Errorf("policy %q: %w", name, err)
		}
	}
	for token, t := range c.Tenants {
		if token == "" || len(token) < 16 {
			return fmt.Errorf("tenant %q: token must be at least 16 random characters", t.Label)
		}
		if _, ok := c.Policies[t.Policy]; !ok {
			return fmt.Errorf("tenant %q: policy %q not found", t.Label, t.Policy)
		}
	}
	return nil
}

func (p *Policy) validate() error {
	if p.EpochSeconds <= 0 {
		return errors.New("epoch_seconds must be > 0")
	}
	if !positive(p.EpochBudgetEpsilon) {
		return errors.New("epoch_budget_epsilon must be > 0")
	}
	if !positive(p.RatePerSecond) {
		return errors.New("rate_per_second must be > 0")
	}
	if p.Burst <= 0 {
		p.Burst = 1
	}
	if p.Energy.Enabled {
		if err := p.Energy.validate(p); err != nil {
			return fmt.Errorf("energy: %w", err)
		}
	}
	if p.Frequency.Enabled {
		if err := p.Frequency.validate(p); err != nil {
			return fmt.Errorf("frequency: %w", err)
		}
	}
	if !p.Energy.Enabled && !p.Frequency.Enabled {
		return errors.New("at least one of energy/frequency must be enabled")
	}

	// Budget shares split the epoch budget between DP-charged features.
	// Nominal-only frequency spends no epsilon and needs no share.
	var shares float64
	nCharged := 0
	if p.Energy.Enabled {
		shares += p.Energy.BudgetShare
		nCharged++
	}
	if p.Frequency.Enabled && !p.Frequency.ExposeNominalOnly {
		shares += p.Frequency.BudgetShare
		nCharged++
	}
	if nCharged > 0 && shares > 1.0001 {
		return fmt.Errorf("budget shares sum to %.3f > 1; epoch composition would exceed budget", shares)
	}
	return nil
}

// maxReleases is the ceiling on snapshots one tenant can obtain per epoch.
// The sanitizer caches one snapshot per window and never charges twice for
// it, so the window cadence - not the request rate - is the hard bound.
func (p *Policy) maxReleases(perWindow int) int {
	return (p.EpochSeconds / perWindow) + 1
}

func (e *EnergyPolicy) validate(p *Policy) error {
	if e.WindowSeconds <= 0 {
		return errors.New("window_seconds must be > 0")
	}
	switch e.Scope {
	case "package", "host":
	case "":
		e.Scope = "package"
	default:
		return fmt.Errorf("scope must be package|host, got %q", e.Scope)
	}
	if e.QuantizeJ < 0 {
		return errors.New("quantize_joules must be >= 0")
	}
	if !positive(e.EnvelopeW) {
		return errors.New("envelope_watts must be > 0")
	}
	if e.DPMode == "" {
		e.DPMode = DPModeSignalBounded
	}
	switch e.DPMode {
	case DPModeSignalBounded:
		if !positive(e.SignalMaxDeltaJ) {
			return errors.New("signal_max_delta_joules required for signal_bounded mode " +
				"(use full_range mode for a model-free guarantee)")
		}
	case DPModeFullRange:
	default:
		return fmt.Errorf("unknown dp_mode %q", e.DPMode)
	}
	if e.BudgetShare <= 0 {
		e.BudgetShare = 1
	}
	e.resolveEpsilon(p, e.WindowSeconds, e.BudgetShare)
	if e.ReleaseEpsilon <= 0 {
		return errors.New("release_epsilon resolution failed")
	}
	// Composition check against this feature's share of the epoch budget.
	maxRel := p.maxReleases(e.WindowSeconds)
	shareBudget := p.EpochBudgetEpsilon * e.BudgetShare
	if got := e.ReleaseEpsilon * float64(maxRel); got > shareBudget*1.0001 {
		return fmt.Errorf("energy budget exceeded: %d releases * eps %.4f = %.4f > share budget %.4f",
			maxRel, e.ReleaseEpsilon, got, shareBudget)
	}
	return nil
}

func (f *FrequencyPolicy) validate(p *Policy) error {
	if f.ExposeNominalOnly {
		// Static answers spend no budget and need no DP configuration.
		if !positive(f.NominalMHz) || !positive(f.MaxMHz) {
			return errors.New("nominal_mhz and max_mhz required for nominal-only mode")
		}
		return nil
	}
	if f.WindowSeconds <= 0 {
		return errors.New("window_seconds must be > 0")
	}
	if f.QuantizeMHz < 0 {
		return errors.New("quantize_mhz must be >= 0")
	}
	if !positive(f.EnvelopeMHz) {
		return errors.New("envelope_mhz must be > 0")
	}
	if f.DPMode == "" {
		f.DPMode = DPModeSignalBounded
	}
	switch f.DPMode {
	case DPModeSignalBounded:
		if !positive(f.SignalMaxDeltaMHz) {
			return errors.New("signal_max_delta_mhz required for signal_bounded mode")
		}
	case DPModeFullRange:
	default:
		return fmt.Errorf("unknown dp_mode %q", f.DPMode)
	}
	if f.BudgetShare <= 0 {
		f.BudgetShare = 1
	}
	f.resolveEpsilon(p, f.WindowSeconds, f.BudgetShare)
	maxRel := p.maxReleases(f.WindowSeconds)
	shareBudget := p.EpochBudgetEpsilon * f.BudgetShare
	if got := f.ReleaseEpsilon * float64(maxRel); got > shareBudget*1.0001 {
		return fmt.Errorf("frequency budget exceeded: %d releases * eps %.4f = %.4f > share budget %.4f",
			maxRel, f.ReleaseEpsilon, got, shareBudget)
	}
	return nil
}

func resolveEpsilon(release *float64, p *Policy, windowSec int, share float64) {
	if *release > 0 {
		return
	}
	maxRel := p.maxReleases(windowSec)
	*release = (p.EpochBudgetEpsilon * share) / float64(maxRel)
}

func (e *EnergyPolicy) resolveEpsilon(p *Policy, windowSec int, share float64) {
	resolveEpsilon(&e.ReleaseEpsilon, p, windowSec, share)
}

func (f *FrequencyPolicy) resolveEpsilon(p *Policy, windowSec int, share float64) {
	resolveEpsilon(&f.ReleaseEpsilon, p, windowSec, share)
}
