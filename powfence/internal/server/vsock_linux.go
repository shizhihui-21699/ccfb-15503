//go:build linux

package server

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// AF_VSOCK constants and sockaddr_vm are not exposed by the standard syscall
// package, so they are declared here alongside the minimal socket/bind/listen
// sequence. The code intentionally depends on no third-party library.
const (
	afVSOCK        = 40
	sockStream     = syscall.SOCK_STREAM
	sockaddrVMSize = 16
	cidAny         = 4294967295 // VMADDR_CID_ANY: bind on every local CID
)

type sockaddrVM struct {
	Family uint16
	Resv1  uint16
	Port   uint32
	CID    uint32
	Zero   [8]byte
}

// bindRaw invokes bind(2) directly because syscall.Bind only accepts the
// Sockaddr types the standard library knows about (no SockaddrVM).
func bindRaw(fd int, sa *sockaddrVM) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_BIND,
		uintptr(fd),
		uintptr(unsafe.Pointer(sa)),
		uintptr(sockaddrVMSize),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// listenVSock creates an AF_VSOCK stream listener.
// addr is "<cid>:<port>"; cid 0 (or "any") binds to VMADDR_CID_ANY, which is
// the setting for a host service accepting guest connections.
func listenVSock(addr string) (net.Listener, error) {
	cidStr, portStr, ok := strings.Cut(addr, ":")
	if !ok {
		return nil, fmt.Errorf("vsock address must be <cid>:<port>, got %q", addr)
	}
	port, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("invalid vsock port %q", portStr)
	}
	cid := uint32(cidAny)
	if cidStr != "" && cidStr != "0" && cidStr != "any" {
		v, err := strconv.ParseUint(cidStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid vsock cid %q", cidStr)
		}
		cid = uint32(v)
	}

	fd, err := syscall.Socket(afVSOCK, sockStream, 0)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_VSOCK): %w (requires a vsock-capable kernel, e.g. vhost_vsock)", err)
	}
	sa := &sockaddrVM{Family: afVSOCK, Port: uint32(port), CID: cid}
	if err := bindRaw(fd, sa); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("bind(AF_VSOCK): %w", err)
	}
	if err := syscall.Listen(fd, syscall.SOMAXCONN); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("listen(AF_VSOCK): %w", err)
	}
	// Wrap the raw fd in an *os.File so net.FileListener takes over deadline
	// and connection management through the runtime network poller.
	f := os.NewFile(uintptr(fd), fmt.Sprintf("vsock:%d", port))
	defer f.Close() // FileListener dupes the fd.
	ln, err := net.FileListener(f)
	if err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	return ln, nil
}
