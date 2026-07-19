package internal

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/system"
	mgmClient "github.com/netbirdio/netbird/shared/management/client"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestSyncSCIONMetaRetriesPublishAndClear(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	succeeded := make(chan string, 2)
	mock := &mgmClient.MockClient{}
	mock.SyncMetaFunc = func(info *system.Info) error {
		call := calls.Add(1)
		if call == 1 || call == 3 {
			return errors.New("transient")
		}
		succeeded <- info.ScionAddress
		return nil
	}
	engine := &Engine{ctx: ctx, config: &EngineConfig{}, mgmClient: mock, syncMsgMux: &sync.Mutex{}, scionMetaChanged: make(chan struct{}, 1)}
	engine.shutdownWg.Add(1)
	go engine.runSCIONMetaWorker()
	engine.queueSCIONMeta("1-ff00:0:110,[192.0.2.1]:30041")
	select {
	case got := <-succeeded:
		if got == "" {
			t.Fatal("publish retry cleared address")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("publish retry did not succeed")
	}
	engine.queueSCIONMeta("")
	select {
	case got := <-succeeded:
		if got != "" {
			t.Fatalf("clear retry published %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("clear retry did not succeed")
	}
	cancel()
	engine.shutdownWg.Wait()
}

func TestSCIONMetaWorkerLifecycleCoalescesWithChecksUpdate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	mock := &mgmClient.MockClient{}
	mock.SyncMetaFunc = func(info *system.Info) error {
		if info.ScionAddress != "" {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
		}
		return nil
	}
	engine := &Engine{ctx: ctx, config: &EngineConfig{}, mgmClient: mock, syncMsgMux: &sync.Mutex{}, scionMetaChanged: make(chan struct{}, 1)}
	engine.shutdownWg.Add(1)
	go engine.runSCIONMetaWorker()
	engine.queueSCIONMeta("1-ff00:0:110,[192.0.2.1]:30041")
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("metadata worker did not start")
	}

	checksDone := make(chan struct{})
	go func() {
		engine.syncMsgMux.Lock()
		_ = engine.updateChecksIfNew([]*mgmProto.Checks{{}})
		engine.syncMsgMux.Unlock()
		close(checksDone)
	}()
	engine.queueSCIONMeta("1-ff00:0:110,[192.0.2.2]:30042")
	cancel()
	close(release)
	select {
	case <-checksDone:
	case <-time.After(5 * time.Second):
		t.Fatal("checks update did not finish")
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := waitWithContext(shutdownCtx, &engine.shutdownWg); err != nil {
		t.Fatalf("metadata worker was not joined: %v", err)
	}
}

func TestPeerRequiresRebuildForSCIONAddress(t *testing.T) {
	const address = "1-ff00:0:110,[192.0.2.1]:30041"
	tests := []struct {
		name, current, update string
		want                  bool
	}{
		{"unchanged", address, address, false},
		{"changed", address, "1-ff00:0:111,[192.0.2.2]:30042", true},
		{"removed", address, "", true},
		{"added", "", address, true},
		{"invalid stays disabled", "", "not-an-address", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			update := &mgmProto.RemotePeerConfig{AgentVersion: "v1", ScionAddress: test.update}
			if got := peerRequiresRebuild("v1", test.current, update); got != test.want {
				t.Fatalf("peerRequiresRebuild() = %v, want %v", got, test.want)
			}
		})
	}
}
