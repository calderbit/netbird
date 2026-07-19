//go:build linux && !android

package net

import "syscall"

// ProtectRawSocket applies NetBird's routing-loop protection to an already-open socket.
func ProtectRawSocket(conn syscall.RawConn, _, _ string) error { return setRawSocketMark(conn) }
