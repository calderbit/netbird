//go:build scion && cgo && (linux || darwin) && !android && !ios

package peer

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/netbirdio/netbird/client/internal/scion"
	"github.com/netbirdio/netbird/shared/scionaddr"
	log "github.com/sirupsen/logrus"
)

func TestWorkerSCIONCloseSerializesWithStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager, err := scion.NewManager(ctx, scion.Config{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	remote := scionaddr.Address{IA: "1-ff00:0:110", Host: netip.MustParseAddrPort("192.0.2.1:30041")}
	worker := NewWorkerSCION(ctx, log.New().WithField("test", "scion"), manager, ConnConfig{SCIONAddress: remote}, &Conn{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); worker.Start() }()
	go func() { defer wg.Done(); worker.Close() }()
	wg.Wait()

	peerConn, err := manager.OpenPeer(ctx, remote, nil)
	if err != nil {
		t.Fatalf("stale worker registration remained after close: %v", err)
	}
	_ = peerConn.Close()
}
