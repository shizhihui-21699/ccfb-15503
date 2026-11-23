//go:build !linux

package source

import "errors"

// NewLinuxSource returns an error on non-Linux platforms. RAPL and cpufreq
// sysfs interfaces are kernel-specific; use the Mock source for local tests.
func NewLinuxSource() (Source, error) {
	return nil, errors.New("hardware RAPL source is only available on Linux")
}
