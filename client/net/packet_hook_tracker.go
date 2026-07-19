//go:build !ios

package net

import (
	"net"
	"sync"

	"github.com/netbirdio/netbird/client/net/hooks"
)

// PacketHookTracker applies legacy-routing hooks to next hops used by packet protocols.
type PacketHookTracker struct {
	id   hooks.ConnectionID
	seen sync.Map
	once sync.Once
}

func NewPacketHookTracker() *PacketHookTracker {
	return &PacketHookTracker{id: hooks.GenerateConnID()}
}

// BeforeWrite applies write hooks once per next-hop address.
func (t *PacketHookTracker) BeforeWrite(address net.Addr) error {
	return callWriteHooks(t.id, &t.seen, address)
}

// Close releases all routing hooks associated with this tracker.
func (t *PacketHookTracker) Close() {
	t.once.Do(func() {
		cleanupConnID(t.id)
		t.seen.Clear()
	})
}
