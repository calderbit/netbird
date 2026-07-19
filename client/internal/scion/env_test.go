package scion

import (
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestResolveConfig(t *testing.T) {
	t.Setenv("NB_SCION", "true")
	t.Setenv("NB_SCION_PREFER", "true")
	t.Setenv("NB_SCION_PORT", "31000")
	t.Setenv("NB_SCION_LISTEN_ADDR", "192.0.2.1")
	t.Setenv("NB_SCION_MAX_PROBE_PATHS", "7")
	t.Setenv("NB_SCION_DIVERSITY_THRESHOLD", "25ms")
	cfg := ResolveConfig(false, "/state/profile")
	if !cfg.Enabled || !cfg.Prefer || cfg.Port != 31000 || cfg.ListenAddr.String() != "192.0.2.1" || cfg.MaxProbePaths != 7 || cfg.DiversityThreshold != 25*time.Millisecond {
		t.Fatalf("unexpected resolved config: %+v", cfg)
	}
	if cfg.StateDir != filepath.Join("/state/profile", "scion") {
		t.Fatalf("unexpected state dir %q", cfg.StateDir)
	}
}

func TestResolveConfigPathsAndBootstrapURLs(t *testing.T) {
	t.Setenv("NB_SCION_STATE_DIR", "/override/state")
	t.Setenv("NB_SCION_TOPOLOGY", "/topology.json")
	t.Setenv("NB_SCION_CERTS_DIR", "/certs")
	t.Setenv("NB_SCION_BOOTSTRAP_URL", "https://single.example")
	t.Setenv("NB_SCION_BOOTSTRAP_URLS", "https://first.example,invalid,http://second.example")
	cfg := ResolveConfig(false, "/profile")
	if cfg.StateDir != "/override/state" || cfg.TopologyPath != "/topology.json" || cfg.CertsDir != "/certs" {
		t.Fatalf("path overrides were not applied: %+v", cfg)
	}
	want := []string{"https://first.example", "http://second.example"}
	if !slices.Equal(cfg.BootstrapURLs, want) {
		t.Fatalf("bootstrap URLs = %v, want %v", cfg.BootstrapURLs, want)
	}
}

func TestResolveConfigInvalidFallsBack(t *testing.T) {
	t.Setenv("NB_SCION", "invalid")
	t.Setenv("NB_SCION_PORT", "70000")
	t.Setenv("NB_SCION_MAX_PROBE_PATHS", "0")
	t.Setenv("NB_SCION_DIVERSITY_THRESHOLD", "invalid")
	t.Setenv("NB_SCION_LISTEN_ADDR", "fe80::1%eth0")
	cfg := ResolveConfig(true, t.TempDir())
	if !cfg.Enabled || cfg.Port != 0 || cfg.MaxProbePaths != 5 || cfg.DiversityThreshold != 50*time.Millisecond {
		t.Fatalf("invalid values did not fall back: %+v", cfg)
	}
}
