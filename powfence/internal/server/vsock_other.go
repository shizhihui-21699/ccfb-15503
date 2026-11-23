//go:build !linux

package server

import (
	"errors"
	"net"
)

// listenVSock is only available on Linux.
func listenVSock(_ string) (net.Listener, error) {
	return nil, errors.New("AF_VSOCK transport is only available on Linux")
}
