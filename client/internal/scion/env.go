package scion

import (
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// ResolveConfig applies validated environment overrides to profile defaults.
func ResolveConfig(profileEnabled bool, profileStateDir string) Config {
	cfg := Config{
		Enabled:            envBool("NB_SCION", profileEnabled),
		Prefer:             envBool("NB_SCION_PREFER", false),
		StateDir:           filepath.Join(profileStateDir, "scion"),
		InterfaceMTU:       1280,
		MaxProbePaths:      5,
		DiversityThreshold: 50 * time.Millisecond,
	}
	if value := os.Getenv("NB_SCION_STATE_DIR"); value != "" {
		cfg.StateDir = value
	}
	cfg.TopologyPath = os.Getenv("NB_SCION_TOPOLOGY")
	cfg.CertsDir = os.Getenv("NB_SCION_CERTS_DIR")
	cfg.BootstrapURLs = envURLs()
	if value := os.Getenv("NB_SCION_LISTEN_ADDR"); value != "" {
		addr, err := netip.ParseAddr(value)
		if err != nil || !addr.IsValid() || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() {
			log.Warnf("ignoring invalid NB_SCION_LISTEN_ADDR %q", value)
		} else {
			cfg.ListenAddr = addr.Unmap()
		}
	}
	cfg.Port = uint16(envUint("NB_SCION_PORT", 0, 0, 65535))
	cfg.MaxProbePaths = int(envUint("NB_SCION_MAX_PROBE_PATHS", uint64(cfg.MaxProbePaths), 1, 64))
	if value := os.Getenv("NB_SCION_DIVERSITY_THRESHOLD"); value != "" {
		d, err := time.ParseDuration(value)
		if err != nil || d < 0 {
			log.Warnf("ignoring invalid NB_SCION_DIVERSITY_THRESHOLD %q", value)
		} else {
			cfg.DiversityThreshold = d
		}
	}
	return cfg
}

func envBool(name string, fallback bool) bool {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		log.Warnf("ignoring invalid %s %q", name, value)
		return fallback
	}
	return parsed
}

func envUint(name string, fallback, min, max uint64) uint64 {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed < min || parsed > max {
		log.Warnf("ignoring invalid %s %q", name, value)
		return fallback
	}
	return parsed
}

func envURLs() []string {
	value := os.Getenv("NB_SCION_BOOTSTRAP_URLS")
	if value == "" {
		value = os.Getenv("NB_SCION_BOOTSTRAP_URL")
	}
	var urls []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		parsed, err := url.Parse(item)
		if item == "" {
			continue
		}
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			log.Warnf("ignoring invalid SCION bootstrap URL %q", item)
			continue
		}
		urls = append(urls, item)
	}
	return urls
}
