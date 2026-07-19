package scionaddr

import "testing"

func TestParseCanonicalizes(t *testing.T) {
	tests := map[string]string{
		"1-FF00:0000:0110,[192.0.2.1]:30042":   "1-ff00:0:110,[192.0.2.1]:30042",
		"001-00042,[::ffff:192.0.2.1]:1":       "1-42,[192.0.2.1]:1",
		"65535-4294967295,[2001:db8::1]:65535": "65535-4294967295,[2001:db8::1]:65535",
	}
	for input, want := range tests {
		got, err := Parse(input)
		if err != nil {
			t.Fatalf("Parse(%q): %v", input, err)
		}
		if got.String() != want {
			t.Errorf("Parse(%q).String() = %q, want %q", input, got, want)
		}
	}
}

func TestParseRejectsInvalid(t *testing.T) {
	for _, input := range []string{
		"", "65536-1,[192.0.2.1]:1", "1-4294967296,[192.0.2.1]:1",
		"1-ff00:0,[192.0.2.1]:1", "1-10000:0:1,[192.0.2.1]:1",
		"1-1,[::]:1", "1-1,[ff02::1]:1", "1-1,[fe80::1%eth0]:1",
		"1-1,[192.0.2.1]:0", "1-1,192.0.2.1:1", string(make([]byte, 257)),
	} {
		if _, err := Parse(input); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded", input)
		}
	}
}
