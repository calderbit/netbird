package peer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	"github.com/netbirdio/netbird/client/internal/peer/conntype"
	"github.com/netbirdio/netbird/client/internal/peer/worker"
	"github.com/netbirdio/netbird/client/internal/scion"
	"github.com/netbirdio/netbird/shared/scionaddr"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestBestTransportPriority(t *testing.T) {
	tests := []struct {
		name                          string
		relay, ice, scion, prefer     bool
		icePriority, expectedPriority conntype.ConnPriority
	}{
		{"relay only", true, false, false, false, conntype.None, conntype.Relay},
		{"normal ICE P2P beats SCION", true, true, true, false, conntype.ICEP2P, conntype.ICEP2P},
		{"preferred SCION keeps ICE standby", true, true, true, true, conntype.ICEP2P, conntype.SCIONPreferred},
		{"SCION beats TURN", true, true, true, false, conntype.ICETurn, conntype.SCION},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := bestTransportPriority(test.relay, test.ice, test.icePriority, test.scion, test.prefer); got != test.expectedPriority {
				t.Fatalf("priority = %s, want %s", got, test.expectedPriority)
			}
		})
	}
}

func TestSCIONWorkerRequiresSupportedAndEnabledManager(t *testing.T) {
	remote := scionaddr.Address{IA: "1-ff00:0:110", Host: netip.MustParseAddrPort("192.0.2.1:30041")}
	if shouldCreateSCIONWorker(scion.State{Supported: false, Enabled: true}, remote) {
		t.Fatal("unsupported manager created SCION worker")
	}
	if shouldCreateSCIONWorker(scion.State{Supported: true, Enabled: false}, remote) {
		t.Fatal("disabled manager created SCION worker")
	}
	if !shouldCreateSCIONWorker(scion.State{Supported: true, Enabled: true}, remote) {
		t.Fatal("supported enabled manager did not create SCION worker")
	}
}

func TestStandbyCredentialsAreDeliveredIndependently(t *testing.T) {
	conn := &Conn{config: ConnConfig{Key: "peer", WgConfig: WgConfig{AllowedIps: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}}}}
	delivered := make(chan struct{}, 1)
	conn.onConnected = func(_ string, key []byte, _ string, address string) {
		if string(key) == "key" && address == "192.0.2.2:9999" {
			delivered <- struct{}{}
		}
	}
	conn.cacheRosenpassCredentialsLocked([]byte("key"), "192.0.2.2:9999")
	conn.notifyRosenpassCredentialsLocked()
	select {
	case <-delivered:
	default:
		t.Fatal("standby credentials were not delivered")
	}
}

func TestSCIONReadinessRequiresReadyPath(t *testing.T) {
	if nextSCIONReady(true, scion.PeerState{Ready: false, AllUnhealthy: false}) {
		t.Fatal("removed active path retained readiness before replacement probes")
	}
	if nextSCIONReady(true, scion.PeerState{AllUnhealthy: true}) {
		t.Fatal("all-unhealthy state retained worker readiness")
	}
	if !nextSCIONReady(false, scion.PeerState{Ready: true}) {
		t.Fatal("healthy path did not make worker ready")
	}
}

type scionTimeoutWGIface struct {
	updateCalls int
	proxy       wgproxy.Proxy
}

func (w *scionTimeoutWGIface) UpdatePeer(string, []netip.Prefix, time.Duration, *net.UDPAddr, *wgtypes.Key) error {
	w.updateCalls++
	if w.updateCalls == 1 {
		return errors.New("transient endpoint update")
	}
	return nil
}
func (*scionTimeoutWGIface) RemovePeer(string) error                          { return nil }
func (*scionTimeoutWGIface) GetStats() (map[string]configurer.WGStats, error) { return nil, nil }
func (w *scionTimeoutWGIface) GetProxy() wgproxy.Proxy                        { return w.proxy }
func (*scionTimeoutWGIface) Address() wgaddr.Address                          { return wgaddr.Address{} }
func (*scionTimeoutWGIface) RemoveEndpointAddress(string) error               { return nil }

type scionTimeoutProxy struct {
	endpoint *net.UDPAddr
	worked   bool
	closed   bool
}

func (*scionTimeoutProxy) AddTurnConn(context.Context, *net.UDPAddr, net.Conn, byte) error {
	return nil
}
func (p *scionTimeoutProxy) EndpointAddr() *net.UDPAddr { return p.endpoint }
func (p *scionTimeoutProxy) Work()                      { p.worked = true }
func (*scionTimeoutProxy) Pause()                       {}
func (*scionTimeoutProxy) RedirectAs(*net.UDPAddr)      {}
func (p *scionTimeoutProxy) CloseConn() error           { p.closed = true; return nil }
func (*scionTimeoutProxy) SetDisconnectListener(func()) {}
func (*scionTimeoutProxy) InjectPacket([]byte) error    { return nil }

func TestWGTimeoutFallbackFailureDoesNotStrandSCIONReplacement(t *testing.T) {
	ctx := context.Background()
	wgIface := &scionTimeoutWGIface{}
	oldProxy := &scionTimeoutProxy{endpoint: &net.UDPAddr{IP: net.IPv4(127, 3, 0, 1), Port: 1}}
	conn := &Conn{
		ctx: ctx,
		Log: log.WithField("test", "scion-timeout"),
		config: ConnConfig{Key: "peer", WgConfig: WgConfig{
			RemoteKey:   "peer",
			WgInterface: wgIface,
			AllowedIps:  []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		}},
		endpointUpdater:     NewEndpointUpdater(log.WithField("test", "scion-timeout"), WgConfig{RemoteKey: "peer", WgInterface: wgIface}, true),
		currentConnPriority: conntype.SCION,
		icePriority:         conntype.ICETurn,
		iceEndpoint:         &net.UDPAddr{IP: net.IPv4(127, 2, 0, 1), Port: 2},
		wgProxySCION:        oldProxy,
		statusRelay:         worker.NewAtomicStatus(),
		statusICE:           worker.NewAtomicStatus(),
		statusSCION:         worker.NewAtomicStatus(),
		metricsStages:       &MetricsStages{},
		workerSCION:         &WorkerSCION{closed: true},
		wgWatcher:           &WGWatcher{},
	}
	conn.statusICE.SetConnected()
	conn.statusSCION.SetConnected()

	conn.onWGDisconnected(ctx)
	if !oldProxy.closed || conn.currentConnPriority != conntype.None {
		t.Fatalf("failed fallback retained stale SCION state: closed=%v priority=%s", oldProxy.closed, conn.currentConnPriority)
	}

	replacement := &scionTimeoutProxy{endpoint: &net.UDPAddr{IP: net.IPv4(127, 3, 0, 2), Port: 3}}
	wgIface.proxy = replacement
	remoteConn := &scion.PeerConn{}
	replacementWorker := &WorkerSCION{ctx: ctx, conn: conn, generation: 1, peerConn: remoteConn}
	conn.workerSCION = replacementWorker
	conn.onSCIONConnectionIsReady(replacementWorker, 1, remoteConn)
	if wgIface.updateCalls != 2 || !replacement.worked || conn.currentConnPriority != conntype.SCION {
		t.Fatalf("replacement was not activated: updates=%d worked=%v priority=%s", wgIface.updateCalls, replacement.worked, conn.currentConnPriority)
	}
}
