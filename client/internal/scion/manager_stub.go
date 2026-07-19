//go:build !scion || !cgo || (!linux && !darwin) || android || ios

package scion

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/netbirdio/netbird/shared/scionaddr"
)

var errUnsupported = errors.New("SCION transport is not compiled for this platform")

func Supported() bool { return false }

type Manager struct{ config Config }

type PeerConn struct{}

func NewManager(_ context.Context, config Config) (*Manager, error) {
	return &Manager{config: config}, nil
}
func (m *Manager) LocalAddress() string { return "" }
func (m *Manager) Prefer() bool         { return m.config.Prefer }
func (m *Manager) OpenPeer(context.Context, scionaddr.Address, func(PeerState)) (*PeerConn, error) {
	return nil, errUnsupported
}
func (m *Manager) Kick()                           {}
func (m *Manager) Status() State                   { return State{Supported: false, Enabled: m.config.Enabled} }
func (m *Manager) Close() error                    { return nil }
func (*PeerConn) Read([]byte) (int, error)         { return 0, errUnsupported }
func (*PeerConn) Write([]byte) (int, error)        { return 0, errUnsupported }
func (*PeerConn) Close() error                     { return nil }
func (*PeerConn) LocalAddr() net.Addr              { return nil }
func (*PeerConn) RemoteAddr() net.Addr             { return nil }
func (*PeerConn) SetDeadline(time.Time) error      { return errUnsupported }
func (*PeerConn) SetReadDeadline(time.Time) error  { return errUnsupported }
func (*PeerConn) SetWriteDeadline(time.Time) error { return errUnsupported }
