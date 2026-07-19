package peer

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/scion"
)

// WorkerSCION owns one peer registration on the shared SCION manager.
type WorkerSCION struct {
	ctx     context.Context
	log     *log.Entry
	manager *scion.Manager
	config  ConnConfig
	conn    *Conn

	startMu      sync.Mutex
	mu           sync.Mutex
	peerConn     *scion.PeerConn
	ready        bool
	allUnhealthy bool
	lastState    scion.PeerState
	generation   uint64
	closed       bool
}

func NewWorkerSCION(ctx context.Context, logger *log.Entry, manager *scion.Manager, config ConnConfig, conn *Conn) *WorkerSCION {
	return &WorkerSCION{ctx: ctx, log: logger, manager: manager, config: config, conn: conn}
}

func (w *WorkerSCION) Start() {
	w.startMu.Lock()
	w.mu.Lock()
	if w.closed || w.peerConn != nil || w.ctx.Err() != nil {
		w.mu.Unlock()
		w.startMu.Unlock()
		return
	}
	w.generation++
	generation := w.generation
	w.mu.Unlock()

	peerConn, err := w.manager.OpenPeer(w.ctx, w.config.SCIONAddress, func(state scion.PeerState) {
		w.onState(generation, state)
	})
	if err != nil {
		w.startMu.Unlock()
		w.log.Debugf("SCION peer unavailable: %v", err)
		return
	}
	w.mu.Lock()
	if w.closed || generation != w.generation || w.ctx.Err() != nil {
		w.mu.Unlock()
		w.startMu.Unlock()
		_ = peerConn.Close()
		return
	}
	w.peerConn = peerConn
	ready, state := w.ready, w.lastState
	w.mu.Unlock()
	w.startMu.Unlock()
	if ready {
		w.conn.onSCIONConnectionIsReady(w, generation, peerConn)
	}
	w.conn.updateSCIONState(w, generation, state)
}

func (w *WorkerSCION) onState(generation uint64, state scion.PeerState) {
	w.mu.Lock()
	if w.closed || generation != w.generation {
		w.mu.Unlock()
		return
	}
	wasReady := w.ready
	w.ready = nextSCIONReady(wasReady, state)
	w.allUnhealthy = state.AllUnhealthy
	w.lastState = state
	ready := w.ready
	peerConn := w.peerConn
	w.mu.Unlock()
	if peerConn == nil {
		return
	}
	if ready && !wasReady {
		w.conn.onSCIONConnectionIsReady(w, generation, peerConn)
	} else if !ready && wasReady {
		w.conn.onSCIONStateDisconnected(w, generation)
	}
	w.conn.updateSCIONState(w, generation, state)
}

func (w *WorkerSCION) isCurrent(generation uint64, peerConn *scion.PeerConn) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return !w.closed && w.generation == generation && (peerConn == nil || w.peerConn == peerConn)
}

func nextSCIONReady(_ bool, state scion.PeerState) bool { return state.Ready }

func (w *WorkerSCION) Reset() {
	w.startMu.Lock()
	defer w.startMu.Unlock()
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.generation++
	peerConn := w.peerConn
	w.peerConn = nil
	w.ready = false
	w.allUnhealthy = false
	w.mu.Unlock()
	if peerConn != nil {
		_ = peerConn.Close()
	}
	go w.Start()
}

func (w *WorkerSCION) Close() {
	w.startMu.Lock()
	defer w.startMu.Unlock()
	w.mu.Lock()
	w.closed = true
	w.generation++
	peerConn := w.peerConn
	w.peerConn = nil
	w.ready = false
	w.allUnhealthy = false
	w.mu.Unlock()
	if peerConn != nil {
		_ = peerConn.Close()
	}
}

func (w *WorkerSCION) Ready() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ready
}

func (w *WorkerSCION) InProgress() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return !w.closed && w.peerConn != nil && !w.ready && !w.allUnhealthy
}
