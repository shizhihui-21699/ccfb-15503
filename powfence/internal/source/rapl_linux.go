//go:build linux

package source

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"powfence/internal/metric"
)

// raplDomain tracks one energy counter file and its wrap-around state.
type raplDomain struct {
	name   string  // stable label, e.g. "package-0", "psys", "amd-hwmon0"
	path   string  // file holding the counter in microjoules
	rangeJ float64 // max range in joules (0 if unknown)
	lastJ  float64 // last unwrapped cumulative value
	primed bool
}

// linuxSource collects RAPL energy and cpufreq frequency from sysfs.
//
// RAPL access was restricted to privileged users by the upstream Platypus
// mitigation (energy_uj is mode 0400 on modern kernels), so the daemon runs
// as a privileged host service and is the ONLY process expected to open these
// files. Guests must not be granted equivalent access; see docs/HARDENING.
type linuxSource struct {
	mu      sync.Mutex
	domains []*raplDomain
	freqCPU []int // logical CPUs exposing scaling_cur_freq

	nominalMHz float64
	maxMHz     float64
}

// NewLinuxSource discovers every available energy counter and cpufreq node.
func NewLinuxSource() (Source, error) {
	s := &linuxSource{}
	if err := s.discoverRAPL(); err != nil {
		return nil, err
	}
	if len(s.domains) == 0 {
		return nil, errors.New("no RAPL/hwmon energy counters found (need Intel powercap or AMD hwmon support)")
	}
	s.discoverFreq()
	if len(s.freqCPU) == 0 {
		return nil, errors.New("no cpufreq scaling_cur_freq nodes found (cpufreq driver required)")
	}
	s.nominalMHz, s.maxMHz = discoverFreqBounds(s.freqCPU[0])
	if s.maxMHz <= 0 {
		return nil, errors.New("could not read cpuinfo_max_freq")
	}
	if s.nominalMHz <= 0 {
		s.nominalMHz = s.maxMHz
	}
	return s, nil
}

const powercapRoot = "/sys/class/powercap"

// discoverRAPL finds Intel powercap domains (package + psys; subdomains such
// as dram/core/uncore are intentionally skipped because fine-grained domains
// carry stronger leakage) and AMD hwmon energy inputs.
func (s *linuxSource) discoverRAPL() error {
	entries, err := os.ReadDir(powercapRoot)
	if err == nil {
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), "intel-rapl:") {
				continue
			}
			dir := filepath.Join(powercapRoot, e.Name())
			name, err := readTrim(filepath.Join(dir, "name"))
			if err != nil {
				continue
			}
			if name != "package" && name != "psys" {
				continue // skip dram / core / uncore subdomains
			}
			counter := filepath.Join(dir, "energy_uj")
			if _, err := os.Stat(counter); err != nil {
				continue
			}
			d := &raplDomain{name: name + "-" + strings.TrimPrefix(e.Name(), "intel-rapl:"), path: counter}
			if rng, err := readFloat(filepath.Join(dir, "max_energy_range_uj")); err == nil {
				d.rangeJ = rng / 1e6
			}
			s.domains = append(s.domains, d)
		}
	}

	// AMD Zen: /sys/class/hwmon/hwmonN/energy*_input (microjoules).
	hwmons, err := filepath.Glob("/sys/class/hwmon/hwmon*")
	if err == nil {
		for i, dir := range hwmons {
			matches, _ := filepath.Glob(filepath.Join(dir, "energy*_input"))
			for _, m := range matches {
				s.domains = append(s.domains, &raplDomain{
					name: fmt.Sprintf("amd-hwmon%d", i),
					path: m,
				})
			}
		}
	}
	return nil
}

// discoverFreq records every CPU with a scaling_cur_freq node.
func (s *linuxSource) discoverFreq() {
	cpus, _ := filepath.Glob("/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq")
	sort.Strings(cpus)
	for _, p := range cpus {
		// .../cpuN/cpufreq/scaling_cur_freq -> N
		parts := strings.Split(p, string(os.PathSeparator))
		var cpu int
		for _, part := range parts {
			if strings.HasPrefix(part, "cpu") {
				if n, err := strconv.Atoi(strings.TrimPrefix(part, "cpu")); err == nil {
					cpu = n
				}
			}
		}
		s.freqCPU = append(s.freqCPU, cpu)
	}
}

func discoverFreqBounds(cpu int) (nominal, max float64) {
	base := fmt.Sprintf("/sys/devices/system/cpu/cpu%d/cpufreq", cpu)
	if v, err := readFloat(filepath.Join(base, "base_frequency")); err == nil {
		nominal = v / 1000 // kHz -> MHz
	}
	if v, err := readFloat(filepath.Join(base, "cpuinfo_max_freq")); err == nil {
		max = v / 1000
	}
	return nominal, max
}

func (s *linuxSource) Collect(_ context.Context) (metric.RawBatch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	batch := metric.RawBatch{
		Counters:    make([]metric.RawCounter, 0, len(s.domains)),
		Frequencies: make([]metric.RawFrequency, 0, len(s.freqCPU)),
	}

	for _, d := range s.domains {
		uj, err := readFloat(d.path)
		if err != nil {
			return batch, fmt.Errorf("rapl %s: %w", d.name, err)
		}
		j := uj / 1e6
		if d.primed && j < d.lastJ {
			// The hardware counter wrapped back to a small value.
			// Unwrap to a monotonic cumulative number.
			if d.rangeJ <= 0 {
				// Range unknown: cannot unwrap safely; skip this tick
				// rather than emit a negative increment downstream.
				continue
			}
			j += d.rangeJ
		}
		d.lastJ = j
		d.primed = true
		batch.Counters = append(batch.Counters, metric.RawCounter{
			Domain: d.name,
			Joules: j,
			T:      now,
		})
	}

	for _, cpu := range s.freqCPU {
		p := fmt.Sprintf("/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq", cpu)
		khz, err := readFloat(p)
		if err != nil {
			continue // one hotplugged CPU must not break the batch
		}
		batch.Frequencies = append(batch.Frequencies, metric.RawFrequency{
			CPU: cpu,
			MHz: khz / 1000,
			T:   now,
		})
	}
	return batch, nil
}

func (s *linuxSource) NominalMHz() float64 { return s.nominalMHz }
func (s *linuxSource) MaxMHz() float64     { return s.maxMHz }
func (s *linuxSource) Close() error        { return nil }

func readTrim(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func readFloat(path string) (float64, error) {
	v, err := readTrim(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseFloat(v, 64)
}
