//go:build scion && cgo && (linux || darwin) && !android && !ios

// SCION transport implementation. Path selection algorithms are adapted from
// netsys-lab/tailscale-scion under the BSD-3-Clause license.
package scion

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/shared/scionaddr"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	daemonapi "github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

const (
	probeSize             = 29
	probePing             = 1
	probePong             = 2
	peerQueueSize         = 64
	pathReevaluationDelay = 2 * time.Second
	softRefreshInterval   = 5 * time.Minute
	discoveryLogInterval  = 5 * time.Minute
	hardRefreshWindow     = time.Minute
)

var probeMagic = [4]byte{0xa5, 0x4e, 0x42, 0x50}

func Supported() bool { return true }

type Manager struct {
	ctx              context.Context
	cancel           context.CancelFunc
	config           Config
	mu               sync.RWMutex
	connector        daemon.Connector
	topology         *daemon.ReloadingTopology
	cooked           *snet.Conn
	localIA          addr.IA
	localAddress     string
	peers            map[string]*PeerConn
	writeMu          sync.Mutex
	closed           atomic.Bool
	reconnecting     atomic.Bool
	unknownDrops     atomic.Uint64
	kick             chan struct{}
	state            State
	probeLimiter     *rate.Limiter
	dropLogLimiter   *rate.Limiter
	discoveryLog     map[string]time.Time
	socketGeneration uint64
	topologyCancel   context.CancelFunc
}

type pathCandidate struct {
	id                                     PathID
	remote                                 *snet.UDPAddr
	fingerprint                            string
	samples                                [8]time.Duration
	sampleCount, sampleNext, losses, pongs int
	pendingNonce                           uint64
	pending                                bool
	pendingAt                              time.Time
	latency                                time.Duration
	expires                                time.Time
	healthy                                bool
}

type pathSnapshot struct {
	id      PathID
	remote  *snet.UDPAddr
	expires time.Time
}

type datagram struct{ data []byte }

var errManagerInactive = errors.New("SCION manager inactive")

type trackedPacketConn struct {
	snet.PacketConn
	tracker *nbnet.PacketHookTracker
}

func (c *trackedPacketConn) WriteTo(packet *snet.Packet, nextHop *net.UDPAddr) error {
	if err := c.tracker.BeforeWrite(nextHop); err != nil {
		log.Debugf("SCION next-hop routing hook failed: %v", err)
	}
	return c.PacketConn.WriteTo(packet, nextHop)
}

func (c *trackedPacketConn) Close() error {
	c.tracker.Close()
	return c.PacketConn.Close()
}

type PeerConn struct {
	manager                     *Manager
	key                         string
	remote                      scionaddr.Address
	callback                    func(PeerState)
	queue                       chan datagram
	closed                      chan struct{}
	closeOnce                   sync.Once
	mu                          sync.RWMutex
	paths                       []*pathCandidate
	active                      *pathCandidate
	readDeadline, writeDeadline time.Time
	deadlineChanged             chan struct{}
	probeLimiter                *rate.Limiter
	dropLogLimiter              *rate.Limiter
	discovering                 atomic.Bool
	dropped                     atomic.Uint64
	lastEvaluation              time.Time
	lastDiscovery               time.Time
	nextRefresh                 time.Time
	refreshFailures             int
	mtuSkipped                  int
	statusReady                 bool
	allUnhealthy                bool
	hardNextRefresh             time.Time
}

func NewManager(parent context.Context, config Config) (*Manager, error) {
	ctx, cancel := context.WithCancel(parent)
	m := &Manager{ctx: ctx, cancel: cancel, config: config, peers: make(map[string]*PeerConn), kick: make(chan struct{}, 1), probeLimiter: rate.NewLimiter(100, 200), dropLogLimiter: rate.NewLimiter(rate.Every(time.Second), 1), discoveryLog: make(map[string]time.Time)}
	m.state = State{Supported: true, Enabled: config.Enabled}
	if config.Enabled {
		go m.run()
		go m.refreshLoop()
	}
	return m, nil
}

func (m *Manager) run() {
	delays := []time.Duration{0, 5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 60 * time.Second}
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			delay := delays[min(attempt, len(delays)-1)]
			select {
			case <-time.After(delay):
			case <-m.ctx.Done():
				return
			}
		}
		if err := m.start(); err != nil {
			m.setError(err)
			continue
		}
		return
	}
}

func (m *Manager) start() error {
	topologyPath := m.config.TopologyPath
	if topologyPath == "" {
		if _, err := os.Stat("/etc/scion/topology.json"); err == nil {
			topologyPath = "/etc/scion/topology.json"
		} else {
			topologyPath = filepath.Join(m.config.StateDir, "topology.json")
		}
	}
	if bootstrapStateStale(topologyPath, m.config.StateDir) {
		urls := append([]string(nil), m.config.BootstrapURLs...)
		if len(urls) == 0 {
			if url, discoverErr := discoverBootstrapURL(m.ctx); discoverErr == nil {
				urls = append(urls, url)
			}
		}
		var bootstrapErr error
		for _, url := range urls {
			if bootstrapErr = bootstrap(m.ctx, url, m.config.StateDir); bootstrapErr == nil {
				topologyPath = filepath.Join(m.config.StateDir, "topology.json")
				break
			}
		}
		if len(urls) > 0 && bootstrapErr != nil {
			return bootstrapErr
		}
	}
	certsDir := m.config.CertsDir
	if certsDir == "" {
		certsDir = filepath.Join(filepath.Dir(topologyPath), "certs")
	}
	asInfo, err := daemon.LoadASInfoFromFile(topologyPath)
	if err != nil {
		return fmt.Errorf("load SCION topology: %w", err)
	}
	connector, err := daemon.NewStandaloneConnector(m.ctx, asInfo, daemon.WithCertsDir(certsDir), daemon.WithPeriodicCleanup())
	if err != nil {
		return fmt.Errorf("start SCION connector: %w", err)
	}
	topo, err := daemon.NewReloadingTopology(m.ctx, connector)
	if err != nil {
		_ = connector.Close()
		return err
	}
	localIA, err := connector.LocalIA(m.ctx)
	if err != nil {
		_ = connector.Close()
		return err
	}
	if m.config.Port != 0 {
		start, end, err := connector.PortRange(m.ctx)
		if err != nil {
			_ = connector.Close()
			return err
		}
		if m.config.Port < start || m.config.Port > end {
			_ = connector.Close()
			return fmt.Errorf("SCION port %d is outside dispatched range %d-%d", m.config.Port, start, end)
		}
	}
	cooked, localAddress, err := m.openSocket(connector, topo, localIA)
	if err != nil {
		_ = connector.Close()
		return err
	}
	topologyCtx, topologyCancel := context.WithCancel(m.ctx)
	m.mu.Lock()
	if m.closed.Load() {
		m.mu.Unlock()
		topologyCancel()
		_ = cooked.Close()
		_ = connector.Close()
		return net.ErrClosed
	}
	m.connector, m.topology, m.localIA, m.topologyCancel = connector, topo, localIA, topologyCancel
	m.mu.Unlock()
	go topo.Run(topologyCtx, 30*time.Second)
	m.installSocket(cooked, localAddress)
	return nil
}

func (m *Manager) openSocket(connector daemon.Connector, topo *daemon.ReloadingTopology, localIA addr.IA) (*snet.Conn, string, error) {
	listenIP, err := m.listenIP(connector)
	if err != nil {
		return nil, "", err
	}
	raw, err := (&snet.SCIONNetwork{
		Topology:    topo.Topology(),
		SCMPHandler: nonPropagatingSCMPHandler(),
	}).OpenRaw(m.ctx, &net.UDPAddr{IP: listenIP.AsSlice(), Port: int(m.config.Port)})
	if err != nil {
		return nil, "", fmt.Errorf("open SCION socket: %w", err)
	}
	rawConn, err := raw.SyscallConn()
	if err != nil {
		_ = raw.Close()
		return nil, "", err
	}
	network := "udp6"
	if listenIP.Is4() {
		network = "udp4"
	}
	if err := nbnet.ProtectRawSocket(rawConn, network, raw.LocalAddr().String()); err != nil {
		_ = raw.Close()
		return nil, "", err
	}
	tracked := &trackedPacketConn{PacketConn: raw, tracker: nbnet.NewPacketHookTracker()}
	cooked, err := snet.NewCookedConn(tracked, topo.Topology())
	if err != nil {
		_ = tracked.Close()
		return nil, "", err
	}
	localHost := cooked.LocalAddr().(*snet.UDPAddr).Host
	localAP := netip.AddrPortFrom(netip.MustParseAddr(localHost.IP.String()).Unmap(), uint16(localHost.Port))
	return cooked, scionaddr.Address{IA: localIA.String(), Host: localAP}.String(), nil
}

func nonPropagatingSCMPHandler() snet.SCMPHandler {
	return snet.SCMPPropagationStopper{Handler: snet.DefaultSCMPHandler{}}
}

func (m *Manager) installSocket(cooked *snet.Conn, localAddress string) {
	m.writeMu.Lock()
	m.mu.Lock()
	if m.closed.Load() {
		m.mu.Unlock()
		m.writeMu.Unlock()
		_ = cooked.Close()
		return
	}
	old := m.cooked
	m.socketGeneration++
	generation := m.socketGeneration
	m.cooked, m.localAddress = cooked, localAddress
	m.state.Active, m.state.LocalIA, m.state.LocalAddress, m.state.LastError = true, m.localIA.String(), localAddress, ""
	peers := make([]*PeerConn, 0, len(m.peers))
	for _, peer := range m.peers {
		peers = append(peers, peer)
	}
	m.mu.Unlock()
	m.writeMu.Unlock()
	if old != nil && old != cooked {
		_ = old.Close()
	}
	m.notifyAddress(localAddress)
	m.updateRefreshHealth()
	m.notifyState()
	go m.receiveLoop(cooked, generation)
	for _, peer := range peers {
		go peer.rediscover(true)
	}
}

func (m *Manager) listenIP(connector daemon.Connector) (netip.Addr, error) {
	if m.config.ListenAddr.IsValid() {
		return m.config.ListenAddr, nil
	}
	interfaces, _ := connector.Interfaces(m.ctx)
	target := netip.MustParseAddrPort("1.1.1.1:53")
	for _, next := range interfaces {
		target = next
		break
	}
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(target))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("select SCION listen address: %w", err)
	}
	defer conn.Close()
	ip, ok := netip.AddrFromSlice(conn.LocalAddr().(*net.UDPAddr).IP)
	if !ok || ip.IsUnspecified() {
		return netip.Addr{}, errors.New("could not select SCION listen address")
	}
	return ip.Unmap(), nil
}

func (m *Manager) receiveLoop(conn *snet.Conn, generation uint64) {
	buffer := make([]byte, 65535)
	for {
		n, source, err := conn.ReadFrom(buffer)
		if err != nil {
			if m.closed.Load() || m.handleSocketReadError(err, generation) {
				return
			}
			log.Debugf("ignored non-terminal SCION receive error: %v", err)
			continue
		}
		remote, ok := source.(*snet.UDPAddr)
		if !ok || remote.Host == nil {
			continue
		}
		key := udpKey(remote)
		m.mu.RLock()
		peer := m.peers[key]
		m.mu.RUnlock()
		if peer == nil {
			drops := m.unknownDrops.Add(1)
			if m.dropLogLimiter.Allow() {
				log.Debugf("dropped %d SCION datagrams from unknown sources", drops)
			}
			continue
		}
		if hasProbeMagic(buffer[:n]) {
			if isProbe(buffer[:n]) {
				peer.handleProbe(buffer[:n], remote)
			} else {
				drops := peer.dropped.Add(1)
				if peer.dropLogLimiter.Allow() {
					log.Debugf("dropped %d malformed SCION probes from %s", drops, key)
				}
			}
			continue
		}
		peer.updateReplyPath(remote)
		data := append([]byte(nil), buffer[:n]...)
		select {
		case peer.queue <- datagram{data}:
		default:
			drops := peer.dropped.Add(1)
			if peer.dropLogLimiter.Allow() {
				log.Debugf("dropped %d SCION datagrams for full peer queue %s", drops, key)
			}
		}
	}
}

func (m *Manager) reconnect(cause error, generation uint64) {
	if m.closed.Load() {
		return
	}
	m.writeMu.Lock()
	m.mu.Lock()
	if m.socketGeneration != generation || m.cooked == nil || !m.reconnecting.CompareAndSwap(false, true) {
		m.mu.Unlock()
		m.writeMu.Unlock()
		return
	}
	old, connector, topo, localIA := m.cooked, m.connector, m.topology, m.localIA
	m.cooked = nil
	m.localAddress = ""
	m.state.Active = false
	m.state.LocalAddress = ""
	m.state.LastError = cause.Error()
	m.mu.Unlock()
	m.writeMu.Unlock()
	_ = old.Close()
	m.notifyAddress("")
	m.updateRefreshHealth()
	m.notifyState()
	go func() {
		if connector != nil && topo != nil {
			ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
			_, connectorErr := connector.LocalIA(ctx)
			cancel()
			if connectorErr == nil {
				if cooked, address, err := m.openSocket(connector, topo, localIA); err == nil {
					m.reconnecting.Store(false)
					m.installSocket(cooked, address)
					return
				}
			}
		}
		m.mu.Lock()
		var topologyCancel context.CancelFunc
		if m.connector == connector {
			m.connector, m.topology = nil, nil
			topologyCancel, m.topologyCancel = m.topologyCancel, nil
		}
		m.mu.Unlock()
		if topologyCancel != nil {
			topologyCancel()
		}
		if connector != nil {
			_ = connector.Close()
		}
		m.reconnecting.Store(false)
		m.run()
	}()
}

func (m *Manager) refreshLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			m.refreshPeers(now, false)
		case <-m.kick:
			m.refreshPeers(time.Now(), true)
		case <-m.ctx.Done():
			return
		}
	}
}

func (m *Manager) refreshPeers(now time.Time, force bool) {
	m.mu.RLock()
	peers := make([]*PeerConn, 0, len(m.peers))
	for _, p := range m.peers {
		peers = append(peers, p)
	}
	m.mu.RUnlock()
	for _, p := range peers {
		if due, hard := p.refreshDue(now, force); due {
			go p.rediscover(hard)
		}
	}
}
func (m *Manager) Kick() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

func (m *Manager) OpenPeer(ctx context.Context, remote scionaddr.Address, callback func(PeerState)) (*PeerConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p := &PeerConn{manager: m, remote: remote, callback: callback, queue: make(chan datagram, peerQueueSize), closed: make(chan struct{}), deadlineChanged: make(chan struct{}, 1), probeLimiter: rate.NewLimiter(10, 20), dropLogLimiter: rate.NewLimiter(rate.Every(time.Second), 1)}
	p.key = addressKey(remote)
	m.mu.Lock()
	if m.closed.Load() {
		m.mu.Unlock()
		return nil, net.ErrClosed
	}
	if _, exists := m.peers[p.key]; exists {
		m.mu.Unlock()
		return nil, fmt.Errorf("SCION peer %s already registered", remote)
	}
	m.peers[p.key] = p
	active := m.cooked != nil
	m.mu.Unlock()
	m.updateConnectedPeers()
	if active {
		if err := p.discover(ctx, false); err != nil {
			p.recordDiscoveryResult(time.Now(), err, false)
			go p.rediscover(false)
		} else {
			p.recordDiscoveryResult(time.Now(), nil, false)
		}
	}
	go p.probeLoop()
	go func() {
		select {
		case <-ctx.Done():
			_ = p.Close()
		case <-p.closed:
		}
	}()
	return p, nil
}

func (p *PeerConn) discover(ctx context.Context, refresh bool) error {
	p.manager.mu.RLock()
	connector, localIA := p.manager.connector, p.manager.localIA
	p.manager.mu.RUnlock()
	if connector == nil {
		return errors.New("SCION manager not active")
	}
	remoteIA, err := addr.ParseIA(p.remote.IA)
	if err != nil {
		return err
	}
	var paths []snet.Path
	if remoteIA != localIA {
		paths, err = connector.Paths(ctx, remoteIA, localIA, daemonapi.PathReqFlags{Refresh: refresh})
		if err != nil {
			return err
		}
	}
	candidates := make([]*pathCandidate, 0, max(1, len(paths)))
	mtuSkipped := 0
	if remoteIA == localIA {
		candidates = append(candidates, &pathCandidate{id: 1, healthy: true, remote: &snet.UDPAddr{IA: remoteIA, Path: snetpath.Empty{}, Host: net.UDPAddrFromAddrPort(p.remote.Host)}})
	} else {
		localAddress, err := scionaddr.Parse(p.manager.LocalAddress())
		if err != nil {
			return err
		}
		usable := make([]snet.Path, 0, len(paths))
		seen := make(map[string]struct{}, len(paths))
		for _, path := range paths {
			meta := path.Metadata()
			if meta == nil || (!meta.Expiry.IsZero() && !time.Now().Before(meta.Expiry)) {
				continue
			}
			fp := meta.Fingerprint().String()
			if _, ok := seen[fp]; ok {
				continue
			}
			seen[fp] = struct{}{}
			if p.manager.config.InterfaceMTU > 0 {
				fits, err := pathFitsMTU(localAddress, p.remote, path.Dataplane(), p.manager.config.InterfaceMTU, meta.MTU)
				if err != nil || !fits {
					mtuSkipped++
					continue
				}
			}
			usable = append(usable, path)
		}
		for _, path := range selectDiversePaths(usable, p.manager.config.MaxProbePaths, p.manager.config.DiversityThreshold) {
			meta := path.Metadata()
			fp := meta.Fingerprint().String()
			candidates = append(candidates, &pathCandidate{id: pathID(fp), fingerprint: fp, expires: meta.Expiry, remote: &snet.UDPAddr{IA: remoteIA, Path: path.Dataplane(), NextHop: path.UnderlayNextHop(), Host: net.UDPAddrFromAddrPort(p.remote.Host)}})
		}
	}
	if len(candidates) == 0 {
		p.mu.Lock()
		p.mtuSkipped = mtuSkipped
		p.mu.Unlock()
		p.manager.updateRefreshHealth()
		return errors.New("no usable SCION path")
	}
	p.mu.Lock()
	p.paths, p.active = reconcileCandidates(p.paths, candidates, p.active)
	p.mtuSkipped = mtuSkipped
	p.mu.Unlock()
	p.manager.updateRefreshHealth()
	p.publish()
	return nil
}
func (p *PeerConn) rediscover(refresh bool) {
	if !p.discovering.CompareAndSwap(false, true) {
		return
	}
	defer p.discovering.Store(false)
	delays := []time.Duration{0, 10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second}
	var lastErr error
	for _, delay := range delays {
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-p.closed:
				return
			case <-p.manager.ctx.Done():
				return
			}
		}
		ctx, cancel := context.WithTimeout(p.manager.ctx, 10*time.Second)
		lastErr = p.discover(ctx, refresh)
		cancel()
		if lastErr == nil {
			p.recordDiscoveryResult(time.Now(), nil, refresh)
			return
		}
	}
	err := fmt.Errorf("SCION path discovery exhausted retries: %w", lastErr)
	p.recordDiscoveryResult(time.Now(), err, refresh)
	if p.manager.shouldLogDiscovery(p.remote.IA, time.Now()) {
		log.Warnf("SCION path discovery for IA %s failed: %v", p.remote.IA, err)
	}
	p.publish()
}

func announcedLatency(path snet.Path) time.Duration {
	const unknownLatency = time.Hour
	meta := path.Metadata()
	if meta == nil || len(meta.Latency) == 0 {
		return unknownLatency
	}
	var total time.Duration
	for _, d := range meta.Latency {
		if d <= 0 {
			return unknownLatency
		}
		total += d
	}
	return total
}
func pathID(fingerprint string) PathID {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(fingerprint); i++ {
		h ^= uint64(fingerprint[i])
		h *= 1099511628211
	}
	if h == 0 {
		h = 1
	}
	return PathID(h)
}
func udpKey(a *snet.UDPAddr) string {
	ip, _ := netip.AddrFromSlice(a.Host.IP)
	return scionaddr.Address{IA: a.IA.String(), Host: netip.AddrPortFrom(ip.Unmap(), uint16(a.Host.Port))}.String()
}
func addressKey(a scionaddr.Address) string { return a.String() }

func (p *PeerConn) probeLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.sendProbes()
		case <-p.closed:
			return
		}
	}
}
func (p *PeerConn) sendProbes() {
	p.mu.Lock()
	now := time.Now()
	expirePendingProbes(p.paths)
	paths := make([]pathSnapshot, 0, len(p.paths))
	for _, candidate := range p.paths {
		paths = append(paths, pathSnapshot{id: candidate.id, remote: candidate.remote, expires: candidate.expires})
	}
	p.mu.Unlock()
	for _, path := range paths {
		if !path.expires.IsZero() && !now.Before(path.expires) {
			go p.rediscover(true)
			continue
		}
		var nonceBytes [8]byte
		if _, err := rand.Read(nonceBytes[:]); err != nil {
			continue
		}
		nonce := binary.BigEndian.Uint64(nonceBytes[:])
		if nonce == 0 {
			nonce = 1
		}
		packet := encodeProbe(probePing, nonce, uint64(time.Since(processStart).Nanoseconds()), path.id)
		p.mu.Lock()
		current := false
		for _, candidate := range p.paths {
			if candidate.id == path.id {
				candidate.pendingNonce = nonce
				candidate.pending = true
				candidate.pendingAt = now
				current = true
				break
			}
		}
		p.mu.Unlock()
		if !current {
			continue
		}
		if _, err := p.writeTo(packet, path.remote, false); err != nil {
			p.recordPathWriteFailure(path.id, err)
		}
	}
	p.choosePath()
	p.publish()
}

func expirePendingProbes(paths []*pathCandidate) {
	for _, c := range paths {
		if c.pending {
			c.losses++
			if c.losses >= 3 {
				c.healthy = false
				c.pongs = 0
			}
			c.pending = false
			c.pendingNonce = 0
		}
	}
}

var processStart = time.Now()

func encodeProbe(kind byte, nonce, timestamp uint64, id PathID) []byte {
	b := make([]byte, probeSize)
	copy(b, probeMagic[:])
	b[4] = kind
	binary.BigEndian.PutUint64(b[5:13], nonce)
	binary.BigEndian.PutUint64(b[13:21], timestamp)
	binary.BigEndian.PutUint64(b[21:29], uint64(id))
	return b
}
func hasProbeMagic(b []byte) bool {
	return len(b) >= len(probeMagic) && string(b[:4]) == string(probeMagic[:])
}
func isProbe(b []byte) bool {
	return len(b) == probeSize && hasProbeMagic(b) && (b[4] == probePing || b[4] == probePong)
}
func (p *PeerConn) updateReplyPath(reply *snet.UDPAddr) {
	p.mu.Lock()
	if p.active != nil {
		p.active.remote = reply
	}
	p.mu.Unlock()
}

func (p *PeerConn) handleProbe(packet []byte, reply *snet.UDPAddr) {
	kind := packet[4]
	nonce := binary.BigEndian.Uint64(packet[5:13])
	id := PathID(binary.BigEndian.Uint64(packet[21:29]))
	if kind == probePing {
		if !p.manager.probeLimiter.Allow() || !p.probeLimiter.Allow() {
			return
		}
		response := append([]byte(nil), packet...)
		response[4] = probePong
		_, _ = p.writeTo(response, reply, false)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.paths {
		if c.id == id && c.pending && nonce != 0 && c.pendingNonce == nonce {
			latency := time.Since(c.pendingAt)
			c.pending = false
			c.pendingNonce = 0
			c.losses = 0
			c.pongs++
			c.healthy = true
			c.samples[c.sampleNext] = latency
			c.sampleNext = (c.sampleNext + 1) % len(c.samples)
			if c.sampleCount < len(c.samples) {
				c.sampleCount++
			}
			values := append([]time.Duration(nil), c.samples[:c.sampleCount]...)
			sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
			c.latency = values[len(values)/2]
			c.remote = reply
			break
		}
	}
}
func (p *PeerConn) choosePath() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	activeValid := p.active != nil && p.active.healthy && p.active.pongs >= 2 && (p.active.expires.IsZero() || now.Before(p.active.expires))
	if activeValid && now.Sub(p.lastEvaluation) < pathReevaluationDelay {
		return
	}
	if activeValid {
		for _, candidate := range p.paths {
			if candidate.pongs == 0 && candidate.losses < 3 {
				return
			}
		}
	}
	p.lastEvaluation = now
	var best *pathCandidate
	for _, c := range p.paths {
		if c.healthy && c.pongs >= 2 && (c.expires.IsZero() || now.Before(c.expires)) && (best == nil || c.latency < best.latency) {
			best = c
		}
	}
	if best == nil {
		if !activeValid {
			p.active = nil
		}
		return
	}
	if !activeValid {
		p.active = best
		return
	}
	improvement := p.active.latency - best.latency
	threshold := max(2*time.Millisecond, p.active.latency/5)
	if improvement >= threshold {
		p.active = best
	}
}
func (p *PeerConn) publish() {
	p.mu.Lock()
	active := p.active
	count := len(p.paths)
	now := time.Now()
	ready := active != nil && active.healthy && active.pongs >= 2 && (active.expires.IsZero() || now.Before(active.expires))
	allUnhealthy := count > 0
	for _, candidate := range p.paths {
		if !candidate.expires.IsZero() && !now.Before(candidate.expires) {
			continue
		}
		if candidate.healthy || candidate.losses < 3 {
			allUnhealthy = false
			break
		}
	}
	state := PeerState{Ready: ready, PathCount: count, AllUnhealthy: allUnhealthy}
	if active != nil {
		state.Path = fmt.Sprintf("%x", active.id)
		state.Latency = active.latency
	}
	readyChanged := p.statusReady != ready
	allUnhealthyChanged := !p.allUnhealthy && allUnhealthy
	p.statusReady = ready
	p.allUnhealthy = allUnhealthy
	p.mu.Unlock()
	if readyChanged {
		p.manager.updateConnectedPeers()
	}
	if p.callback != nil {
		p.callback(state)
	}
	if allUnhealthyChanged && p.manager != nil {
		go p.rediscover(true)
	}
}
func (p *PeerConn) writeTo(data []byte, remote *snet.UDPAddr, usePeerDeadline bool) (int, error) {
	p.manager.writeMu.Lock()
	p.manager.mu.RLock()
	conn, generation := p.manager.cooked, p.manager.socketGeneration
	p.manager.mu.RUnlock()
	if conn == nil {
		p.manager.writeMu.Unlock()
		return 0, errManagerInactive
	}
	if usePeerDeadline {
		p.mu.RLock()
		deadline := p.writeDeadline
		p.mu.RUnlock()
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			p.manager.writeMu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
	}
	n, err := conn.WriteTo(data, remote)
	p.manager.writeMu.Unlock()
	p.manager.handleSocketWriteError(err, generation)
	return n, err
}

func (m *Manager) handleSocketReadError(err error, generation uint64) bool {
	if !isTerminalSocketError(err) {
		return false
	}
	m.reconnect(err, generation)
	return true
}

func (m *Manager) handleSocketWriteError(err error, generation uint64) {
	if isTerminalSocketError(err) {
		m.reconnect(err, generation)
	}
}

func isTerminalSocketError(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.ENOTSOCK)
}

func (p *PeerConn) recordPathWriteFailure(id PathID, err error) {
	if err == nil || isTerminalSocketError(err) || errors.Is(err, errManagerInactive) || errors.Is(err, os.ErrDeadlineExceeded) {
		return
	}
	p.mu.Lock()
	failed := false
	rediscover := false
	for _, candidate := range p.paths {
		if candidate.id != id {
			continue
		}
		candidate.pending = false
		candidate.pendingNonce = 0
		candidate.losses++
		if candidate.losses >= 3 {
			candidate.healthy = false
			candidate.pongs = 0
			rediscover = true
		}
		failed = true
		break
	}
	p.mu.Unlock()
	if !failed {
		return
	}
	p.choosePath()
	p.publish()
	if rediscover {
		go p.rediscover(true)
	}
}
func (p *PeerConn) Read(b []byte) (int, error) {
	for {
		p.mu.RLock()
		deadline := p.readDeadline
		p.mu.RUnlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case msg := <-p.queue:
			if timer != nil {
				timer.Stop()
			}
			if len(b) < len(msg.data) {
				return 0, io.ErrShortBuffer
			}
			return copy(b, msg.data), nil
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		case <-p.deadlineChanged:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-p.closed:
			if timer != nil {
				timer.Stop()
			}
			return 0, net.ErrClosed
		}
	}
}
func (p *PeerConn) Write(b []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	p.mu.RLock()
	var active pathSnapshot
	if p.active != nil {
		active = pathSnapshot{id: p.active.id, remote: p.active.remote, expires: p.active.expires}
	}
	p.mu.RUnlock()
	if active.id == 0 {
		return 0, errors.New("no SCION path")
	}
	if !active.expires.IsZero() && !time.Now().Before(active.expires) {
		go p.rediscover(true)
		return 0, errors.New("active SCION path expired")
	}
	n, err := p.writeTo(b, active.remote, true)
	if err != nil {
		p.recordPathWriteFailure(active.id, err)
	}
	return n, err
}
func (p *PeerConn) Close() error {
	p.closeOnce.Do(func() {
		close(p.closed)
		p.manager.mu.Lock()
		delete(p.manager.peers, p.key)
		p.manager.mu.Unlock()
		p.manager.updateConnectedPeers()
	})
	return nil
}
func (p *PeerConn) LocalAddr() net.Addr {
	p.manager.mu.RLock()
	defer p.manager.mu.RUnlock()
	if p.manager.cooked == nil {
		return nil
	}
	return p.manager.cooked.LocalAddr()
}
func (p *PeerConn) RemoteAddr() net.Addr {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.active == nil {
		return nil
	}
	return p.active.remote
}
func (p *PeerConn) notifyDeadlineChanged() {
	select {
	case p.deadlineChanged <- struct{}{}:
	default:
	}
}
func (p *PeerConn) SetDeadline(t time.Time) error {
	p.mu.Lock()
	p.readDeadline = t
	p.writeDeadline = t
	p.mu.Unlock()
	p.notifyDeadlineChanged()
	return nil
}
func (p *PeerConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.readDeadline = t
	p.mu.Unlock()
	p.notifyDeadlineChanged()
	return nil
}
func (p *PeerConn) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	p.writeDeadline = t
	p.mu.Unlock()
	p.notifyDeadlineChanged()
	return nil
}

func (m *Manager) LocalAddress() string { m.mu.RLock(); defer m.mu.RUnlock(); return m.localAddress }
func (m *Manager) Prefer() bool         { return m.config.Prefer }
func (m *Manager) Status() State        { m.mu.RLock(); defer m.mu.RUnlock(); return m.state }
func (m *Manager) setError(err error) {
	m.mu.Lock()
	m.state.LastError = err.Error()
	m.mu.Unlock()
	m.notifyState()
}
func (m *Manager) notifyAddress(value string) {
	if m.config.OnAddressChange != nil {
		m.config.OnAddressChange(value)
	}
}
func (m *Manager) notifyState() {
	if m.config.OnStatusChange != nil {
		m.config.OnStatusChange(m.Status())
	}
}
func (m *Manager) Close() error {
	if !m.closed.CompareAndSwap(false, true) {
		return nil
	}
	m.cancel()
	m.writeMu.Lock()
	m.mu.Lock()
	conn, connector, topologyCancel := m.cooked, m.connector, m.topologyCancel
	m.cooked, m.connector, m.topology, m.topologyCancel = nil, nil, nil, nil
	m.socketGeneration++
	m.localAddress = ""
	m.state.Active = false
	m.state.LocalAddress = ""
	peers := make([]*PeerConn, 0, len(m.peers))
	for _, p := range m.peers {
		peers = append(peers, p)
	}
	m.mu.Unlock()
	m.writeMu.Unlock()
	if topologyCancel != nil {
		topologyCancel()
	}
	for _, p := range peers {
		_ = p.Close()
	}
	var err error
	if conn != nil {
		err = conn.Close()
	}
	if connector != nil {
		err = errors.Join(err, connector.Close())
	}
	m.notifyAddress("")
	m.updateRefreshHealth()
	m.notifyState()
	return err
}
