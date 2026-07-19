package bind

import (
	"net"
	"testing"
)

func TestFakeAddressPrefixSeparatesTransports(t *testing.T) {
	peer := &net.UDPAddr{IP: net.ParseIP("100.64.1.2"), Port: 51820}
	relay, err := fakeAddress(peer, 1)
	if err != nil {
		t.Fatal(err)
	}
	scion, err := fakeAddress(peer, 3)
	if err != nil {
		t.Fatal(err)
	}
	if relay.Addr().String() != "127.1.1.2" || scion.Addr().String() != "127.3.1.2" || relay == scion {
		t.Fatalf("unexpected fake endpoints: relay=%s SCION=%s", relay, scion)
	}
	for _, invalid := range []byte{0, 255} {
		if _, err := fakeAddress(peer, invalid); err == nil {
			t.Errorf("prefix %d accepted", invalid)
		}
	}
}
