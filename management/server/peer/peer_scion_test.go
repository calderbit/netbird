package peer

import "testing"

func TestSCIONMetadataDiffAndEmpty(t *testing.T) {
	const address = "1-ff00:0:110,[192.0.2.1]:30041"
	if !(PeerSystemMeta{}).isEmpty() {
		t.Fatal("zero metadata is not empty")
	}
	oldMeta := PeerSystemMeta{ScionAddress: address}
	if oldMeta.isEmpty() {
		t.Fatal("SCION-only metadata was treated as empty")
	}
	diff := diffMeta(oldMeta, PeerSystemMeta{}, Location{}, Location{})
	if len(diff.Changed) != 1 || diff.Changed[0] != "scion_address: 1-ff00:0:110,[192.0.2.1]:30041 -> " {
		t.Fatalf("address removal diff = %#v", diff.Changed)
	}
	if !(&MetaDiff{OldMeta: oldMeta, NewMeta: PeerSystemMeta{}}).ScionChanged() {
		t.Fatal("address removal was not reported as changed")
	}
}
