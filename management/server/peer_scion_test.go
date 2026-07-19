package server

import (
	"context"
	"testing"
)

func TestRequiresPeerUpdateForSCIONChange(t *testing.T) {
	if !requiresPeerUpdate(context.Background(), false, false, false, false, false, false, true) {
		t.Fatal("SCION-only metadata change did not require peer fan-out")
	}
	if requiresPeerUpdate(context.Background(), false, false, false, false, false, false, false) {
		t.Fatal("unchanged metadata required peer fan-out")
	}
}
