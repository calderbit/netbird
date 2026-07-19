//go:build !ios

package net

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/netbirdio/netbird/client/net/hooks"
)

func TestPacketHookTracker(t *testing.T) {
	hooks.RemoveWriteHooks()
	hooks.RemoveCloseHooks()
	t.Cleanup(func() { hooks.RemoveWriteHooks(); hooks.RemoveCloseHooks() })
	var writes, closes atomic.Int32
	hooks.AddWriteHook(func(hooks.ConnectionID, netip.Prefix) error { writes.Add(1); return nil })
	hooks.AddCloseHook(func(hooks.ConnectionID) error { closes.Add(1); return nil })
	tracker := NewPacketHookTracker()
	address := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 30041}
	if err := tracker.BeforeWrite(address); err != nil {
		t.Fatal(err)
	}
	if err := tracker.BeforeWrite(address); err != nil {
		t.Fatal(err)
	}
	tracker.Close()
	tracker.Close()
	if writes.Load() != 1 || closes.Load() != 1 {
		t.Fatalf("writes=%d closes=%d", writes.Load(), closes.Load())
	}
}
