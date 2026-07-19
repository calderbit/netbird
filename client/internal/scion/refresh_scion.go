//go:build scion && cgo && (linux || darwin) && !android && !ios

package scion

import (
	"fmt"
	"time"
)

func (p *PeerConn) refreshDue(now time.Time, force bool) (bool, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if force {
		return true, true
	}
	softDue := p.nextRefresh.IsZero() || !now.Before(p.nextRefresh)
	hardDue := p.hardNextRefresh.IsZero() || !now.Before(p.hardNextRefresh)
	if hardDue {
		for _, candidate := range p.paths {
			if !candidate.expires.IsZero() && candidate.expires.Sub(now) <= hardRefreshWindow {
				return true, true
			}
		}
	}
	return softDue, false
}

func (p *PeerConn) recordDiscoveryResult(now time.Time, err error, hard bool) {
	p.mu.Lock()
	if err == nil {
		p.lastDiscovery = now
		p.nextRefresh = now.Add(softRefreshInterval)
		p.hardNextRefresh = time.Time{}
		p.refreshFailures = 0
	} else {
		p.refreshFailures++
		if hard {
			p.hardNextRefresh = now.Add(refreshBackoff(p.refreshFailures))
		} else {
			p.nextRefresh = now.Add(refreshBackoff(p.refreshFailures))
		}
	}
	p.mu.Unlock()
	p.manager.updateRefreshHealth()
}

func refreshBackoff(failures int) time.Duration {
	if failures < 1 {
		return 0
	}
	delay := 10 * time.Second
	for i := 1; i < failures && delay < softRefreshInterval; i++ {
		delay *= 2
	}
	return min(delay, softRefreshInterval)
}

func (m *Manager) updateConnectedPeers() {
	m.mu.RLock()
	peers := make([]*PeerConn, 0, len(m.peers))
	for _, peer := range m.peers {
		peers = append(peers, peer)
	}
	m.mu.RUnlock()

	connected := 0
	for _, peer := range peers {
		peer.mu.RLock()
		if peer.statusReady {
			connected++
		}
		peer.mu.RUnlock()
	}
	m.mu.Lock()
	changed := m.state.ConnectedPeers != connected
	m.state.ConnectedPeers = connected
	m.mu.Unlock()
	if changed {
		m.notifyState()
	}
}

func (m *Manager) updateRefreshHealth() {
	m.mu.RLock()
	active := m.state.Active
	peers := make([]*PeerConn, 0, len(m.peers))
	for _, peer := range m.peers {
		peers = append(peers, peer)
	}
	m.mu.RUnlock()

	failures, mtuSkipped := 0, 0
	for _, peer := range peers {
		peer.mu.RLock()
		failures += peer.refreshFailures
		mtuSkipped += peer.mtuSkipped
		peer.mu.RUnlock()
	}
	health := "inactive"
	if active {
		switch {
		case failures > 0 && mtuSkipped > 0:
			health = fmt.Sprintf("degraded: %d refresh failures; %d paths skipped for MTU", failures, mtuSkipped)
		case failures > 0:
			health = fmt.Sprintf("degraded: %d refresh failures", failures)
		case mtuSkipped > 0:
			health = fmt.Sprintf("healthy: %d paths skipped for MTU", mtuSkipped)
		default:
			health = "healthy"
		}
	}

	m.mu.Lock()
	changed := m.state.RefreshHealth != health
	m.state.RefreshHealth = health
	m.mu.Unlock()
	if changed {
		m.notifyState()
	}
}

func (m *Manager) shouldLogDiscovery(ia string, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if last := m.discoveryLog[ia]; !last.IsZero() && now.Sub(last) < discoveryLogInterval {
		return false
	}
	m.discoveryLog[ia] = now
	return true
}
