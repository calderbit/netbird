//go:build scion && cgo && (linux || darwin) && !android && !ios

// Adapted from netsys-lab/tailscale-scion, BSD-3-Clause.
package scion

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	bootstrapHTTPTimeout = 10 * time.Second
	bootstrapFileLimit   = 1 << 20
	bootstrapTotalLimit  = 16 << 20
	bootstrapTRCLimit    = 64
	bootstrapVersion     = 2
)

type trcEntry struct {
	ID trcID `json:"id"`
}
type trcID struct {
	ISD          int `json:"isd"`
	BaseNumber   int `json:"base_number"`
	SerialNumber int `json:"serial_number"`
}

func (id trcID) String() string {
	return fmt.Sprintf("isd%d-b%d-s%d", id.ISD, id.BaseNumber, id.SerialNumber)
}

func bootstrapStateStale(topologyPath, directory string) bool {
	if _, err := os.Stat(topologyPath); err != nil {
		return true
	}
	if filepath.Clean(topologyPath) != filepath.Join(filepath.Clean(directory), "topology.json") {
		return false
	}
	data, err := os.ReadFile(filepath.Join(directory, "version.json"))
	if err != nil {
		return true
	}
	var stamp struct {
		Version int `json:"version"`
	}
	return json.Unmarshal(data, &stamp) != nil || stamp.Version != bootstrapVersion
}

func bootstrap(ctx context.Context, baseURL, directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	client := &http.Client{Timeout: bootstrapHTTPTimeout}
	total := 0
	topology, consumed, err := fetchBootstrapFile(ctx, client, strings.TrimRight(baseURL, "/")+"/topology", bootstrapFileLimit, bootstrapTotalLimit-total)
	total += consumed
	if err != nil {
		return err
	}
	index, consumed, err := fetchBootstrapFile(ctx, client, strings.TrimRight(baseURL, "/")+"/trcs", bootstrapFileLimit, bootstrapTotalLimit-total)
	total += consumed
	if err != nil {
		return err
	}
	var entries []trcEntry
	if err := json.Unmarshal(index, &entries); err != nil {
		return fmt.Errorf("parse TRC index: %w", err)
	}
	if len(entries) > bootstrapTRCLimit {
		entries = entries[:bootstrapTRCLimit]
	}
	tmp, err := os.MkdirTemp(filepath.Dir(directory), ".scion-bootstrap-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	certs := filepath.Join(tmp, "certs")
	if err := os.MkdirAll(certs, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmp, "topology.json"), topology, 0o644); err != nil {
		return err
	}
	fetched := 0
	for _, entry := range entries {
		remaining := bootstrapTotalLimit - total
		if remaining <= 0 {
			break
		}
		if entry.ID.ISD <= 0 {
			continue
		}
		blob, consumed, err := fetchBootstrapFile(ctx, client, strings.TrimRight(baseURL, "/")+"/trcs/"+entry.ID.String()+"/blob", bootstrapFileLimit, remaining)
		total += consumed
		if err != nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(certs, entry.ID.String()+".trc"), blob, 0o644); err != nil {
			continue
		}
		fetched++
	}
	if fetched == 0 {
		return fmt.Errorf("bootstrap returned no TRCs")
	}
	stamp, _ := json.Marshal(map[string]int{"version": bootstrapVersion})
	if err := os.WriteFile(filepath.Join(tmp, "version.json"), stamp, 0o644); err != nil {
		return err
	}
	old := directory + ".old"
	_ = os.RemoveAll(old)
	if _, err := os.Stat(directory); err == nil {
		if err := os.Rename(directory, old); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, directory); err != nil {
		_ = os.Rename(old, directory)
		return err
	}
	return os.RemoveAll(old)
}

func fetchBootstrapFile(ctx context.Context, client *http.Client, url string, fileLimit, remaining int) ([]byte, int, error) {
	limit := min(fileLimit, remaining)
	if limit <= 0 {
		return nil, 0, fmt.Errorf("bootstrap aggregate budget exceeded")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	// Reading at most limit bytes makes the aggregate bound a bound on bytes
	// actually downloaded, not just on files eventually accepted.
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)))
	if err != nil {
		return nil, len(data), err
	}
	if resp.ContentLength >= 0 {
		if resp.ContentLength > int64(limit) || int64(len(data)) != resp.ContentLength {
			return nil, len(data), fmt.Errorf("GET %s reaches bootstrap byte limit", url)
		}
	} else if len(data) == limit {
		return nil, len(data), fmt.Errorf("GET %s reaches bootstrap byte limit", url)
	}
	return data, len(data), nil
}

func fetchBounded(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	data, err := fetchAtMost(ctx, client, url, limit+1)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("GET %s exceeds %d bytes", url, limit)
	}
	return data, nil
}

func fetchAtMost(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}
