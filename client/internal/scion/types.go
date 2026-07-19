package scion

import (
	"net/netip"
	"time"
)

// Config contains the dependency-free SCION transport configuration.
type Config struct {
	Enabled, Prefer                  bool
	StateDir, TopologyPath, CertsDir string
	BootstrapURLs                    []string
	ListenAddr                       netip.Addr
	Port                             uint16
	InterfaceMTU                     uint16
	MaxProbePaths                    int
	DiversityThreshold               time.Duration
	OnAddressChange                  func(string)
	OnStatusChange                   func(State)
}

// State is the local transport status exposed to the daemon.
type State struct {
	Supported, Enabled, Active bool
	LocalIA, LocalAddress      string
	ConnectedPeers             int
	LastError, RefreshHealth   string
}

// PeerState describes one remote peer's path health.
type PeerState struct {
	Ready        bool
	Path         string
	Latency      time.Duration
	PathCount    int
	AllUnhealthy bool
}

type PathID uint64
