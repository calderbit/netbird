//go:build darwin

package net

import "syscall"

// ProtectRawSocket applies NetBird's routing-loop protection to an already-open socket.
func ProtectRawSocket(conn syscall.RawConn, network, address string) error {
	return applyBoundIfToSocket(network, address, conn)
}
