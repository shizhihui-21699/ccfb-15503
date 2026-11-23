// Package server exposes sanitized telemetry over a local, mutually
// authenticated HTTP API and owns the per-tenant sanitizer lifecycle.
//
// Endpoints (all require a bearer token bound to a tenant policy):
//
//	GET /v1/metrics         -> current sanitized window reading
//	GET /v1/metrics/energy  -> energy subset
//	GET /v1/metrics/freq    -> frequency subset
//	GET /v1/budget          -> remaining privacy budget for the epoch
//
// The API never accepts parameters: scope, window size, quantization and
// epsilon are all fixed server-side by policy. Allowing tenants to choose
// them would re-open the side channel (e.g. requesting 1 ms windows).
package server

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"powfence/internal/audit"
	"powfence/internal/dp"
	"powfence/internal/policy"
	"powfence/internal/sanitize"
	"powfence/internal/source"
)

// Server wires tenants, sanitizers and the audit log into an HTTP handler.
type Server struct {
	cfg      *policy.Config
	tenants  map[string]*tenantState
	auditLog *audit.Logger
	listener net.Listener
}

type tenantState struct {
	label string
	pol   *policy.Policy
	san   *sanitize.Sanitizer
}

// New constructs sanitizers for every configured tenant. The source is
// accepted to make the data-flow dependency explicit at the call site even
// though the server itself only touches the shared ring.
func New(cfg *policy.Config, ring *sanitize.Ring, _ source.Source,
	rng dp.Rand, auditLog *audit.Logger) *Server {
	s := &Server{
		cfg:      cfg,
		tenants:  map[string]*tenantState{},
		auditLog: auditLog,
	}
	for token, t := range cfg.Tenants {
		pol := cfg.Policies[t.Policy]
		s.tenants[token] = &tenantState{
			label: t.Label,
			pol:   pol,
			san:   sanitize.New(pol, ring, rng),
		}
	}
	return s
}

// Listen creates the configured transport listener.
func (s *Server) Listen() (net.Listener, error) {
	switch s.cfg.Listen.Transport {
	case "unix":
		// A stale socket file from an unclean shutdown must not block start.
		if err := os.Remove(s.cfg.Listen.Address); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		ln, err := net.Listen("unix", s.cfg.Listen.Address)
		if err != nil {
			return nil, err
		}
		// Only host-root and the proxy group may connect.
		if err := os.Chmod(s.cfg.Listen.Address, 0o660); err != nil {
			_ = ln.Close()
			return nil, err
		}
		return ln, nil
	case "tcp":
		// TCP is supported for lab use only; production deployments should
		// use a unix socket or vsock and, if TCP is unavoidable, bind a
		// loopback address and enforce mTLS at an upstream sidecar.
		if !strings.HasPrefix(s.cfg.Listen.Address, "127.") &&
			!strings.HasPrefix(s.cfg.Listen.Address, "localhost") {
			return nil, errors.New("refusing non-loopback TCP listener; use unix or vsock transport")
		}
		return net.Listen("tcp", s.cfg.Listen.Address)
	case "vsock":
		return listenVSock(s.cfg.Listen.Address)
	default:
		return nil, errors.New("unknown transport: " + s.cfg.Listen.Transport)
	}
}

// Handler returns the http.Handler (also used by in-process tests).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/metrics", s.auth(s.handleMetrics))
	mux.HandleFunc("/v1/metrics/energy", s.auth(s.handleEnergy))
	mux.HandleFunc("/v1/metrics/freq", s.auth(s.handleFreq))
	mux.HandleFunc("/v1/budget", s.auth(s.handleBudget))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return mux
}

// auth wraps a handler with bearer-token authentication. The token is a
// deployment secret compared with constant-time comparison via
// subtle.ConstantTimeCompare (wrapped in authenticate).
func (s *Server) auth(next func(http.ResponseWriter, *http.Request, *tenantState)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ts, ok := s.authenticate(r)
		if !ok {
			s.auditLog.Log(audit.Event{Action: "deny_auth", Reason: "invalid or missing bearer token"})
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r, ts)
	}
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request, ts *tenantState) {
	s.serveReading(w, r, ts, false, false)
}

func (s *Server) handleEnergy(w http.ResponseWriter, r *http.Request, ts *tenantState) {
	s.serveReading(w, r, ts, true, false)
}

func (s *Server) handleFreq(w http.ResponseWriter, r *http.Request, ts *tenantState) {
	s.serveReading(w, r, ts, false, true)
}

func (s *Server) serveReading(w http.ResponseWriter, r *http.Request,
	ts *tenantState, energyOnly, freqOnly bool) {
	reading, err := ts.san.GetReading(time.Now())
	if err != nil {
		switch {
		case errors.Is(err, sanitize.ErrRateLimited):
			s.auditLog.Log(audit.Event{
				Tenant: ts.label, Action: "deny_rate",
				Policy: ts.pol.Name, Feature: "all",
			})
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
			return
		case errors.Is(err, sanitize.ErrBudgetExhausted):
			s.auditLog.Log(audit.Event{
				Tenant: ts.label, Action: "deny_budget",
				Policy: ts.pol.Name, Feature: "all",
			})
			w.Header().Set("Retry-After", "60")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "budget_exhausted"})
			return
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
			return
		}
	}

	if energyOnly {
		reading.FreqMHz = nil
		reading.NominalMHz = 0
		reading.MaxMHz = 0
	}
	if freqOnly {
		reading.EnergyJ = nil
		reading.AveragePowerW = nil
	}

	s.auditLog.Log(audit.Event{
		Tenant:    ts.label,
		Action:    "release",
		Policy:    ts.pol.Name,
		Epsilon:   reading.EpsilonSpent,
		WindowSec: int(reading.WindowEnd.Sub(reading.WindowStart).Seconds()),
	})
	writeJSON(w, http.StatusOK, reading)
}

// authenticate extracts "Authorization: Bearer <token>" and looks it up with
// a constant-time comparison so token guessing cannot use response timing.
func (s *Server) authenticate(r *http.Request) (*tenantState, bool) {
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(header) <= len(prefix) || header[:len(prefix)] != prefix {
		return nil, false
	}
	presented := header[len(prefix):]
	for token, ts := range s.tenants {
		if subtle.ConstantTimeCompare([]byte(presented), []byte(token)) == 1 {
			return ts, true
		}
	}
	return nil, false
}

func (s *Server) handleBudget(w http.ResponseWriter, r *http.Request, ts *tenantState) {
	// Budget is a policy value, not a hardware value; exposing it cannot
	// leak anything about another tenant or the host workload.
	writeJSON(w, http.StatusOK, map[string]any{
		"policy":             ts.pol.Name,
		"epoch_seconds":      ts.pol.EpochSeconds,
		"epoch_budget":       ts.pol.EpochBudgetEpsilon,
		"rate_per_second":    ts.pol.RatePerSecond,
		"energy_window_s":    ternary(ts.pol.Energy.Enabled, ts.pol.Energy.WindowSeconds, 0),
		"frequency_window_s": ternary(ts.pol.Frequency.Enabled, ts.pol.Frequency.WindowSeconds, 0),
	})
}

func ternary(cond bool, a, b int) int {
	if cond {
		return a
	}
	return b
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
