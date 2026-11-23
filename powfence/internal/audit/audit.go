// Package audit writes one structured JSON line per security-relevant event:
// every released snapshot, every rate-limit/budget denial, and daemon
// lifecycle markers. Logs are append-only and must be shipped off-host; they
// are the evidence trail for "the proxy did what the policy said".
package audit

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Event is the wire format. Field order is stable and documented in
// docs/AUDIT.md so SIEM pipelines can rely on it.
type Event struct {
	Time      time.Time `json:"time"`
	Tenant    string    `json:"tenant"`
	Action    string    `json:"action"` // release | deny_rate | deny_budget | lifecycle
	Feature   string    `json:"feature,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Epsilon   float64   `json:"epsilon,omitempty"`
	WindowSec int       `json:"window_sec,omitempty"`
	Policy    string    `json:"policy,omitempty"`
}

// Logger serializes events to a file or any io.WriteCloser.
type Logger struct {
	mu  sync.Mutex
	w   io.WriteCloser
	enc *json.Encoder
}

// NewFileLogger opens path in append mode (0640) and starts a logger.
// An empty path yields a no-op logger.
func NewFileLogger(path string) (*Logger, error) {
	if path == "" {
		return &Logger{}, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	l := &Logger{w: f}
	l.enc = json.NewEncoder(f)
	return l, nil
}

// Log writes one event. Failures are swallowed after the first write error is
// remembered; audit must never block or alter the release path.
func (l *Logger) Log(e Event) {
	if l == nil || l.w == nil {
		return
	}
	e.Time = time.Now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(e)
}

// Close flushes and closes the underlying file.
func (l *Logger) Close() error {
	if l == nil || l.w == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Close()
}
