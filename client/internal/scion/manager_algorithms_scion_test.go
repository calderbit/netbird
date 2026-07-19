//go:build scion && cgo && (linux || darwin) && !android && !ios

package scion

import (
	"context"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/snet"
)

func TestDisabledManagerReportsInitialState(t *testing.T) {
	manager, err := NewManager(context.Background(), Config{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	state := manager.Status()
	if !state.Supported || state.Enabled || state.Active {
		t.Fatalf("unexpected disabled manager state: %+v", state)
	}
}

func TestChoosePathReevaluationThrottle(t *testing.T) {
	slow := &pathCandidate{id: 1, healthy: true, pongs: 2, latency: 20 * time.Millisecond}
	fast := &pathCandidate{id: 2, healthy: true, pongs: 2, latency: time.Millisecond}
	peer := &PeerConn{paths: []*pathCandidate{slow, fast}, active: slow, lastEvaluation: time.Now()}
	peer.choosePath()
	if peer.active != slow {
		t.Fatal("path switched inside the two-second throttle")
	}
	peer.lastEvaluation = time.Now().Add(-pathReevaluationDelay)
	peer.choosePath()
	if peer.active != fast {
		t.Fatal("better path was not selected after the throttle")
	}
}

func TestChoosePathReplacesExpiredActiveWithoutThrottle(t *testing.T) {
	expired := &pathCandidate{id: 1, healthy: true, pongs: 2, latency: time.Millisecond, expires: time.Now().Add(-time.Second)}
	standby := &pathCandidate{id: 2, healthy: true, pongs: 2, latency: 20 * time.Millisecond, expires: time.Now().Add(time.Minute)}
	peer := &PeerConn{paths: []*pathCandidate{expired, standby}, active: expired, lastEvaluation: time.Now()}
	peer.choosePath()
	if peer.active != standby {
		t.Fatal("expired active path was retained over healthy standby")
	}
}

func TestPublishAllUnhealthySemantics(t *testing.T) {
	var got PeerState
	peer := &PeerConn{callback: func(state PeerState) { got = state }}
	peer.paths = []*pathCandidate{{losses: 2}}
	peer.publish()
	if got.AllUnhealthy {
		t.Fatal("an unsampled path was reported unhealthy before three losses")
	}
	peer.paths[0].losses = 3
	peer.publish()
	if !got.AllUnhealthy {
		t.Fatal("three-loss path was not reported unhealthy")
	}
	peer.paths = append(peer.paths, &pathCandidate{healthy: true, pongs: 1})
	peer.publish()
	if got.AllUnhealthy || got.Ready {
		t.Fatal("a recovering one-pong path is neither ready nor all-unhealthy")
	}
	peer.paths = []*pathCandidate{{healthy: true, pongs: 2, expires: time.Now().Add(-time.Second)}}
	peer.publish()
	if !got.AllUnhealthy || got.Ready {
		t.Fatal("expired path was reported healthy")
	}
}

func TestReconcileCandidatesKeepsStablePathState(t *testing.T) {
	oldRemote := &snet.UDPAddr{}
	newRemote := &snet.UDPAddr{}
	old := &pathCandidate{id: 7, fingerprint: "same", remote: oldRemote, pongs: 4, latency: 3 * time.Millisecond}
	paths, active := reconcileCandidates([]*pathCandidate{old}, []*pathCandidate{{id: 7, fingerprint: "same", remote: newRemote}}, old)
	if paths[0] != old || active != old || old.remote != newRemote || old.pongs != 4 {
		t.Fatal("re-signed path did not retain stable health and active identity")
	}

	replacement := &pathCandidate{id: 8, fingerprint: "new"}
	_, active = reconcileCandidates(paths, []*pathCandidate{replacement}, old)
	if active != nil {
		t.Fatal("unprobed replacement was activated")
	}
}

func TestPathSnapshotsRaceWithReplyDiscoveryProbeAndWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := &Manager{ctx: ctx, peers: make(map[string]*PeerConn), discoveryLog: make(map[string]time.Time)}
	candidate := &pathCandidate{id: 7, fingerprint: "stable", remote: &snet.UDPAddr{}, expires: time.Now().Add(time.Hour), healthy: true, pongs: 2}
	peer := &PeerConn{manager: manager, paths: []*pathCandidate{candidate}, active: candidate, closed: make(chan struct{}), deadlineChanged: make(chan struct{}, 1)}
	manager.peers["peer"] = peer

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			peer.updateReplyPath(&snet.UDPAddr{})
			peer.mu.Lock()
			peer.paths, peer.active = reconcileCandidates(peer.paths, []*pathCandidate{{id: 7, fingerprint: "stable", remote: &snet.UDPAddr{}, expires: time.Now().Add(time.Hour)}}, peer.active)
			peer.mu.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			peer.sendProbes()
			_, _ = peer.Write([]byte("data"))
		}
	}()
	wg.Wait()
}

func TestTerminalSocketErrorClassification(t *testing.T) {
	for _, err := range []error{net.ErrClosed, syscall.EBADF, syscall.ENOTSOCK} {
		if !isTerminalSocketError(err) {
			t.Errorf("terminal socket error %v was not classified for reconnect", err)
		}
	}
	for _, err := range []error{syscall.ENETUNREACH, syscall.EINVAL, context.DeadlineExceeded} {
		if isTerminalSocketError(err) {
			t.Errorf("path/local error %v was classified for manager reconnect", err)
		}
	}
}

func TestSCMPPathLocalReceiveErrorKeepsSharedSocketGenerationAndPeers(t *testing.T) {
	packet := &snet.Packet{PacketInfo: snet.PacketInfo{Payload: snet.SCMPExternalInterfaceDown{}}}
	if err := nonPropagatingSCMPHandler().Handle(packet); err != nil {
		t.Fatalf("SCMP path error propagated to receive loop: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	manager := &Manager{ctx: ctx, peers: make(map[string]*PeerConn), cooked: &snet.Conn{}, socketGeneration: 9}
	first := &PeerConn{manager: manager, paths: []*pathCandidate{{id: 1, healthy: true, pongs: 2}}, statusReady: true}
	second := &PeerConn{manager: manager, paths: []*pathCandidate{{id: 2, healthy: true, pongs: 2}}, statusReady: true}
	manager.peers["first-peer"] = first
	manager.peers["second-peer"] = second
	originalSocket := manager.cooked

	if manager.handleSocketReadError(syscall.ENETUNREACH, manager.socketGeneration) {
		t.Fatal("path-local receive error stopped the shared receive loop")
	}
	if manager.cooked != originalSocket || manager.socketGeneration != 9 {
		t.Fatal("path-local receive error replaced the manager-wide socket")
	}
	if !first.paths[0].healthy || !first.statusReady || !second.paths[0].healthy || !second.statusReady {
		t.Fatal("path-local receive error affected a healthy peer")
	}
}

func TestPathLocalWriteFailureKeepsSharedSocketAndHealthyPeers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	manager := &Manager{ctx: ctx, peers: make(map[string]*PeerConn), cooked: &snet.Conn{}, socketGeneration: 9}
	failed := &pathCandidate{id: 1, healthy: true, pongs: 2, latency: time.Millisecond}
	standby := &pathCandidate{id: 2, healthy: true, pongs: 2, latency: 2 * time.Millisecond}
	peer := &PeerConn{manager: manager, paths: []*pathCandidate{failed, standby}, active: failed}
	healthy := &PeerConn{manager: manager, paths: []*pathCandidate{{id: 3, healthy: true, pongs: 2}}, statusReady: true}
	manager.peers["failed-path"] = peer
	manager.peers["healthy-peer"] = healthy
	originalSocket := manager.cooked

	manager.handleSocketWriteError(syscall.ENETUNREACH, manager.socketGeneration)
	for i := 0; i < 3; i++ {
		peer.recordPathWriteFailure(failed.id, syscall.ENETUNREACH)
	}

	if manager.cooked != originalSocket || manager.socketGeneration != 9 {
		t.Fatal("path-local failure replaced the manager-wide socket")
	}
	if peer.active != standby || !standby.healthy {
		t.Fatal("path-local failure did not preserve the healthy standby")
	}
	if !healthy.paths[0].healthy || !healthy.statusReady {
		t.Fatal("path-local failure affected an unrelated healthy peer")
	}
}

func TestRefreshBackoffAndSoftRefresh(t *testing.T) {
	want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second, 5 * time.Minute}
	for i, expected := range want {
		if got := refreshBackoff(i + 1); got != expected {
			t.Fatalf("failure %d backoff = %s, want %s", i+1, got, expected)
		}
	}
	manager := &Manager{peers: make(map[string]*PeerConn), discoveryLog: make(map[string]time.Time)}
	peer := &PeerConn{manager: manager}
	otherIA := &PeerConn{manager: manager}
	now := time.Now()
	peer.recordDiscoveryResult(now, nil, false)
	if !peer.nextRefresh.Equal(now.Add(softRefreshInterval)) {
		t.Fatalf("next soft refresh = %s", peer.nextRefresh)
	}
	peer.recordDiscoveryResult(now, context.DeadlineExceeded, false)
	if otherIA.refreshFailures != 0 || !otherIA.nextRefresh.IsZero() {
		t.Fatal("one peer/IA refresh backoff affected another")
	}
}

func TestHardRefreshDueBeforeExpiry(t *testing.T) {
	now := time.Now()
	peer := &PeerConn{manager: &Manager{peers: make(map[string]*PeerConn)}, nextRefresh: now.Add(softRefreshInterval), paths: []*pathCandidate{{expires: now.Add(30 * time.Second)}}}
	due, hard := peer.refreshDue(now, false)
	if !due || !hard {
		t.Fatal("near-expiry path did not request a hard refresh")
	}
	peer.recordDiscoveryResult(now, context.DeadlineExceeded, true)
	if due, _ := peer.refreshDue(now.Add(time.Second), false); due {
		t.Fatal("hard-refresh failure ignored backoff")
	}
}

func TestMutableReadDeadlineWakesBlockedRead(t *testing.T) {
	peer := &PeerConn{queue: make(chan datagram, 1), closed: make(chan struct{}), deadlineChanged: make(chan struct{}, 1)}
	done := make(chan error, 1)
	go func() {
		_, err := peer.Read(make([]byte, 1))
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)
	_ = peer.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("updated deadline returned no error")
		}
	case <-time.After(time.Second):
		t.Fatal("updated deadline did not wake blocked read")
	}
}

func TestDiscoveryLogThrottleIsPerIA(t *testing.T) {
	manager := &Manager{discoveryLog: make(map[string]time.Time)}
	now := time.Now()
	if !manager.shouldLogDiscovery("1-ff00:0:110", now) || manager.shouldLogDiscovery("1-ff00:0:110", now.Add(time.Minute)) {
		t.Fatal("same IA was not throttled")
	}
	if !manager.shouldLogDiscovery("1-ff00:0:111", now.Add(time.Minute)) {
		t.Fatal("one IA throttled another")
	}
	if !manager.shouldLogDiscovery("1-ff00:0:110", now.Add(discoveryLogInterval)) {
		t.Fatal("IA log throttle did not expire")
	}
}

func TestRefreshHealthIncludesFailuresAndMTU(t *testing.T) {
	manager := &Manager{peers: make(map[string]*PeerConn), state: State{Active: true}}
	manager.peers["peer"] = &PeerConn{refreshFailures: 2, mtuSkipped: 3}
	manager.updateRefreshHealth()
	if got := manager.Status().RefreshHealth; !strings.Contains(got, "2 refresh failures") || !strings.Contains(got, "3 paths skipped for MTU") {
		t.Fatalf("unexpected refresh health %q", got)
	}
}

type fakeBootstrapResolver struct {
	srvs []*net.SRV
	txts []string
}

func (r fakeBootstrapResolver) LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error) {
	return "", r.srvs, nil
}
func (r fakeBootstrapResolver) LookupTXT(context.Context, string) ([]string, error) {
	return r.txts, nil
}

func TestDiscoverBootstrapURLFromSRV(t *testing.T) {
	resolver := fakeBootstrapResolver{srvs: []*net.SRV{{Target: "bootstrap.example.", Port: 8041}}, txts: []string{"x-sciondiscovery=8042"}}
	got, err := discoverBootstrapURLForDomain(context.Background(), resolver, "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://bootstrap.example:8042" {
		t.Fatalf("bootstrap URL = %q", got)
	}
}
