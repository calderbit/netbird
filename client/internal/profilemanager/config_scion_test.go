package profilemanager

import (
	"path/filepath"
	"testing"
)

func TestScionEnabledRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	enabled := true
	cfg, err := UpdateOrCreateConfig(ConfigInput{ConfigPath: path, ScionEnabled: &enabled})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ScionEnabled {
		t.Fatal("SCION enablement was not persisted")
	}
	cfg, err = UpdateOrCreateConfig(ConfigInput{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ScionEnabled {
		t.Fatal("SCION enablement did not round trip")
	}
}
