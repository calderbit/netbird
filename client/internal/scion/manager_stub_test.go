//go:build !scion || !cgo || (!linux && !darwin) || android || ios

package scion

import (
	"context"
	"testing"
)

func TestStubManagerReportsInitialState(t *testing.T) {
	manager, err := NewManager(context.Background(), Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	state := manager.Status()
	if state.Supported || !state.Enabled {
		t.Fatalf("unexpected stub state: %+v", state)
	}
}
