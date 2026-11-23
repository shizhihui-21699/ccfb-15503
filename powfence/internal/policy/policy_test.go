package policy

import "testing"

func baseConfig() *Config {
	c := &Config{
		Source: "mock",
		Policies: map[string]*Policy{
			"p": {
				Name: "p", EpochSeconds: 3600, EpochBudgetEpsilon: 360,
				RatePerSecond: 2, Burst: 2,
				Energy: EnergyPolicy{
					Enabled: true, Scope: "package", WindowSeconds: 1,
					QuantizeJ: 1, DPMode: DPModeSignalBounded,
					SignalMaxDeltaJ: 0.05, EnvelopeW: 250, BudgetShare: 0.5,
				},
				Frequency: FrequencyPolicy{
					Enabled: true, WindowSeconds: 1, QuantizeMHz: 25,
					DPMode: DPModeSignalBounded, SignalMaxDeltaMHz: 1,
					EnvelopeMHz: 3500, NominalMHz: 2500, MaxMHz: 3500,
					BudgetShare: 0.5,
				},
			},
		},
		Tenants: map[string]Tenant{
			"0123456789abcdef0123456789abcdef": {Policy: "p", Label: "t1"},
		},
	}
	return c
}

func TestValidConfig(t *testing.T) {
	if err := baseConfig().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestRejectsBadTransport(t *testing.T) {
	c := baseConfig()
	c.Listen.Transport = "carrier-pigeon"
	if err := c.Validate(); err == nil {
		t.Fatal("bad transport should be rejected")
	}
}

func TestRejectsShortToken(t *testing.T) {
	c := baseConfig()
	c.Tenants = map[string]Tenant{"short": {Policy: "p"}}
	if err := c.Validate(); err == nil {
		t.Fatal("short token should be rejected")
	}
}

func TestRejectsUnknownPolicyReference(t *testing.T) {
	c := baseConfig()
	c.Tenants["0123456789abcdef0123456789abcdef"] = Tenant{Policy: "missing"}
	if err := c.Validate(); err == nil {
		t.Fatal("unknown policy reference should be rejected")
	}
}

func TestRejectsMissingSensitivity(t *testing.T) {
	c := baseConfig()
	c.Policies["p"].Energy.SignalMaxDeltaJ = 0
	if err := c.Validate(); err == nil {
		t.Fatal("signal_bounded mode without sensitivity should be rejected")
	}
}

func TestFullRangeDoesNotNeedSignal(t *testing.T) {
	c := baseConfig()
	c.Policies["p"].Energy.DPMode = DPModeFullRange
	c.Policies["p"].Energy.SignalMaxDeltaJ = 0
	c.Policies["p"].Frequency.DPMode = DPModeFullRange
	c.Policies["p"].Frequency.SignalMaxDeltaMHz = 0
	if err := c.Validate(); err != nil {
		t.Fatalf("full_range without signal bound rejected: %v", err)
	}
}

func TestBudgetSharesRejectedWhenOverOne(t *testing.T) {
	c := baseConfig()
	c.Policies["p"].Energy.BudgetShare = 0.8
	c.Policies["p"].Frequency.BudgetShare = 0.8
	if err := c.Validate(); err == nil {
		t.Fatal("shares summing above 1 must be rejected")
	}
}

func TestEpsilonCompositionEnforced(t *testing.T) {
	c := baseConfig()
	// An explicit per-release epsilon that exceeds the hourly share when
	// composed over 3601 windows must be rejected at validation time.
	c.Policies["p"].Energy.ReleaseEpsilon = 10
	if err := c.Validate(); err == nil {
		t.Fatal("epsilon exceeding epoch composition must be rejected")
	}
}

func TestEpsilonDerivedWhenOmitted(t *testing.T) {
	c := baseConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	p := c.Policies["p"]
	if p.Energy.ReleaseEpsilon <= 0 || p.Frequency.ReleaseEpsilon <= 0 {
		t.Fatal("derived release epsilon must be positive")
	}
	// Derived epsilon * max releases must fit the feature's budget share.
	maxRel := p.maxReleases(1)
	if got := p.Energy.ReleaseEpsilon * float64(maxRel); got > p.EpochBudgetEpsilon*0.5*1.0001 {
		t.Fatalf("derived energy epsilon over budget: %v", got)
	}
}

func TestNominalOnlyNeedsNoBudget(t *testing.T) {
	c := baseConfig()
	c.Policies["p"].Frequency.ExposeNominalOnly = true
	c.Policies["p"].Frequency.BudgetShare = 0
	c.Policies["p"].Energy.BudgetShare = 1
	if err := c.Validate(); err != nil {
		t.Fatalf("nominal-only without frequency share rejected: %v", err)
	}
}
