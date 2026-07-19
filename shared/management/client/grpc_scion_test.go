package client

import (
	"slices"
	"testing"

	"github.com/netbirdio/netbird/client/system"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestInfoToMetaDataMapsSCION(t *testing.T) {
	const address = "1-ff00:0:110,[192.0.2.1]:30041"
	meta := infoToMetaData(&system.Info{ScionSupported: true, ScionAddress: address, DisableIPv6: true})
	if meta.GetScionAddress() != address {
		t.Fatalf("SCION address = %q", meta.GetScionAddress())
	}
	if !slices.Contains(meta.GetCapabilities(), mgmProto.PeerCapability_PeerCapabilityScion) {
		t.Fatal("compiled SCION capability was not mapped")
	}
}
