package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"powfence/internal/dp"
	"powfence/internal/policy"
	"powfence/internal/sanitize"
	"powfence/internal/source"
)

func mustRNG(t *testing.T) dp.Rand {
	t.Helper()
	rng, err := dp.NewSecureRand()
	if err != nil {
		t.Fatalf("rng: %v", err)
	}
	return rng
}

const testToken = "0123456789abcdef0123456789abcdef"

func testServer(t *testing.T) (*Server, *sanitize.Ring) {
	t.Helper()
	pol := &policy.Policy{
		Name: "p", EpochSeconds: 3600, EpochBudgetEpsilon: 360,
		RatePerSecond: 100, Burst: 100,
		Energy: policy.EnergyPolicy{
			Enabled: true, Scope: "package", WindowSeconds: 1, QuantizeJ: 1,
			DPMode: policy.DPModeSignalBounded, SignalMaxDeltaJ: 0.05,
			EnvelopeW: 250, BudgetShare: 0.5,
		},
		Frequency: policy.FrequencyPolicy{
			Enabled: true, WindowSeconds: 1, QuantizeMHz: 25,
			DPMode: policy.DPModeSignalBounded, SignalMaxDeltaMHz: 1,
			EnvelopeMHz: 3500, NominalMHz: 2500, MaxMHz: 3500, BudgetShare: 0.5,
		},
	}
	cfg := &policy.Config{
		Source:   "mock",
		Policies: map[string]*policy.Policy{"p": pol},
		Tenants:  map[string]policy.Tenant{testToken: {Policy: "p", Label: "tt"}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	ring := sanitize.NewRing(4096)
	mock := source.NewMock()
	// Align synthetic ticks to the most recent completed wall-clock window
	// so the sanitizer's real-time lookup finds them.
	now := time.Now().UTC()
	curStart := time.Unix(now.Unix()-now.Unix()%1, 0)
	for w := 0; w < 3; w++ {
		wStart := curStart.Add(time.Duration(w-2) * time.Second)
		for k := 0; k < 10; k++ {
			ring.PushForTest(sanitize.TickForTest{
				Seq:     uint64(w*10 + k + 1),
				T:       wStart.Add(time.Duration(k) * 100 * time.Millisecond),
				EnergyJ: 12,
				FreqMHz: 2800,
			})
		}
	}
	return New(cfg, ring, mock, mustRNG(t), nil), ring
}

func TestAuthRejectsMissingAndBadToken(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()

	for _, header := range []string{"", "Bearer wrong-token-value", "Basic abc"} {
		req := httptest.NewRequest(http.MethodGet, "/v1/metrics", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("header %q: status = %d, want 401", header, rec.Code)
		}
	}
}

func TestHealthzIsUnauthenticated(t *testing.T) {
	srv, _ := testServer(t)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", rec.Code)
	}
}

func TestAuthenticatedMetrics(t *testing.T) {
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var reading map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &reading); err != nil {
		t.Fatal(err)
	}
	if reading["energy_joules"] == nil || reading["freq_mhz"] == nil {
		t.Fatalf("reading missing fields: %v", reading)
	}
	if reading["window_start"] == nil || reading["window_end"] == nil {
		t.Fatal("reading must identify its window")
	}
}

func TestBudgetEndpoint(t *testing.T) {
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/budget", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["epoch_budget"] != 360.0 {
		t.Fatalf("budget = %v, want 360", body["epoch_budget"])
	}
}

func TestLoopbackOnlyTCPGuard(t *testing.T) {
	cfg := &policy.Config{}
	cfg.Source = "mock"
	cfg.Listen.Transport = "tcp"
	cfg.Listen.Address = "8.8.8.8:9100"
	srv := New(cfg, nil, nil, mustRNG(t), nil)
	if _, err := srv.Listen(); err == nil {
		t.Fatal("non-loopback TCP bind must be refused")
	}
}
