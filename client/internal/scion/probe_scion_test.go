//go:build scion && cgo && (linux || darwin) && !android && !ios

package scion

import (
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestProbeCodec(t *testing.T) {
	packet := encodeProbe(probePing, 42, 99, PathID(7))
	if len(packet) != probeSize || !isProbe(packet) {
		t.Fatalf("invalid encoded probe: %x", packet)
	}
	if packet[4] != probePing || binary.BigEndian.Uint64(packet[5:13]) != 42 || binary.BigEndian.Uint64(packet[13:21]) != 99 || binary.BigEndian.Uint64(packet[21:29]) != 7 {
		t.Fatalf("probe fields did not round trip: %x", packet)
	}
	packet[4] = 3
	if isProbe(packet) {
		t.Fatal("unknown probe type accepted")
	}
}

func TestMalformedMagicProbeIsClassifiedForDrop(t *testing.T) {
	for _, packet := range [][]byte{
		probeMagic[:],
		append(append([]byte(nil), probeMagic[:]...), 9),
		append(encodeProbe(probePing, 1, 2, 3), 0),
	} {
		if !hasProbeMagic(packet) || isProbe(packet) {
			t.Fatalf("malformed magic packet classification failed: %x", packet)
		}
	}
}

func TestPongRequiresOutstandingNonzeroNonceAndTwoPongRecovery(t *testing.T) {
	candidate := &pathCandidate{id: 7, healthy: true, pongs: 4, losses: 2, pending: true, pendingNonce: 99}
	expirePendingProbes([]*pathCandidate{candidate})
	if candidate.healthy || candidate.pongs != 0 || candidate.pending {
		t.Fatal("three losses did not reset probe readiness")
	}
	peer := &PeerConn{paths: []*pathCandidate{candidate}, probeLimiter: rate.NewLimiter(10, 20)}
	peer.handleProbe(encodeProbe(probePong, 0, 0, candidate.id), nil)
	if candidate.pongs != 0 {
		t.Fatal("unsolicited zero-nonce pong was accepted")
	}
	for want := 1; want <= 2; want++ {
		candidate.pending = true
		candidate.pendingNonce = uint64(want)
		candidate.pendingAt = time.Now()
		peer.handleProbe(encodeProbe(probePong, uint64(want), 0, candidate.id), nil)
		peer.handleProbe(encodeProbe(probePong, uint64(want), 0, candidate.id), nil)
		if candidate.pongs != want {
			t.Fatalf("pong/replay count = %d, want %d", candidate.pongs, want)
		}
	}
	peer.choosePath()
	if peer.active != candidate {
		t.Fatal("path did not recover after exactly two fresh pongs")
	}
}

func FuzzProbeClassification(f *testing.F) {
	f.Add(encodeProbe(probePong, 1, 2, 3))
	f.Add([]byte{0xa5, 0x4e, 0x42, 0x50})
	f.Fuzz(func(t *testing.T, packet []byte) {
		accepted := isProbe(packet)
		if accepted && (len(packet) != probeSize || packet[4] < probePing || packet[4] > probePong) {
			t.Fatal("invalid packet accepted")
		}
	})
}
