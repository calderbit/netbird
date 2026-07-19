//go:build scion && cgo && (linux || darwin) && !android && !ios

package scion

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestBootstrapWritesBoundedState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/topology":
			_, _ = w.Write([]byte(`{"isd_as":"1-ff00:0:110"}`))
		case "/trcs":
			_, _ = w.Write([]byte(`[{"id":{"isd":1,"base_number":1,"serial_number":1}}]`))
		case "/trcs/isd1-b1-s1/blob":
			_, _ = w.Write([]byte("trc"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	directory := filepath.Join(t.TempDir(), "state")
	if err := bootstrap(context.Background(), server.URL, directory); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"topology.json", "version.json", filepath.Join("certs", "isd1-b1-s1.trc")} {
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Errorf("missing %s: %v", name, err)
		}
	}
}

func TestBootstrapAggregateBudgetCountsRejectedBlobs(t *testing.T) {
	var blobRequests atomic.Int32
	entries := make([]string, bootstrapTRCLimit)
	for i := range entries {
		entries[i] = fmt.Sprintf(`{"id":{"isd":1,"base_number":1,"serial_number":%d}}`, i+1)
	}
	index := "[" + strings.Join(entries, ",") + "]"
	blob := strings.Repeat("x", bootstrapFileLimit)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/topology":
			_, _ = w.Write([]byte(`{"isd_as":"1-ff00:0:110"}`))
		case "/trcs":
			_, _ = w.Write([]byte(index))
		default:
			blobRequests.Add(1)
			_, _ = w.Write([]byte(blob))
		}
	}))
	defer server.Close()
	if err := bootstrap(context.Background(), server.URL, filepath.Join(t.TempDir(), "state")); err == nil {
		t.Fatal("bootstrap with only limit-sized rejected TRCs succeeded")
	}
	if got := blobRequests.Load(); got > 16 {
		t.Fatalf("bootstrap fetched %d maximum blobs, aggregate budget was bypassed", got)
	}
}

func TestBootstrapStateStale(t *testing.T) {
	directory := t.TempDir()
	topology := filepath.Join(directory, "topology.json")
	if err := os.WriteFile(topology, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !bootstrapStateStale(topology, directory) {
		t.Fatal("missing schema stamp was accepted")
	}
	if err := os.WriteFile(filepath.Join(directory, "version.json"), []byte(`{"version":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if bootstrapStateStale(topology, directory) {
		t.Fatal("current schema stamp was treated as stale")
	}
}

func TestFetchBoundedRejectsOversize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "12345")
	}))
	defer server.Close()
	if _, err := fetchBounded(context.Background(), server.Client(), server.URL, 4); err == nil {
		t.Fatal("oversized response accepted")
	}
}
