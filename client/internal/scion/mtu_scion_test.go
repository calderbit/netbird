//go:build scion && cgo && (linux || darwin) && !android && !ios

package scion

import (
	"net/netip"
	"testing"

	"github.com/netbirdio/netbird/shared/scionaddr"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

func TestSerializedPacketSizeBoundary(t *testing.T) {
	local := scionaddr.Address{IA: "1-ff00:0:110", Host: netip.MustParseAddrPort("192.0.2.1:30041")}
	remote := scionaddr.Address{IA: "1-ff00:0:110", Host: netip.MustParseAddrPort("[2001:db8::1]:30042")}
	size, err := serializedPacketSize(local, remote, snetpath.Empty{}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	if size <= 1280+32+8 {
		t.Fatalf("serialized size %d omitted SCION/address overhead", size)
	}
	if size > 65535 {
		t.Fatalf("serialized test packet too large: %d", size)
	}
	fits, err := pathFitsMTU(local, remote, snetpath.Empty{}, 1280, uint16(size))
	if err != nil || !fits {
		t.Fatalf("exact-fit MTU rejected: fits=%v err=%v", fits, err)
	}
	fits, err = pathFitsMTU(local, remote, snetpath.Empty{}, 1280, uint16(size-1))
	if err != nil || fits {
		t.Fatalf("one-byte-small MTU accepted: fits=%v err=%v", fits, err)
	}
}
