package encoding

import "testing"

func TestStringRoundTrip(t *testing.T) {
	for _, s := range []string{"", "a", "SSH_GATEWAY_USER_IP", string(make([]byte, 1024))} {
		out, rest, ok := ParseString(String(s))
		if !ok || out != s || len(rest) != 0 {
			t.Errorf("round trip of %d bytes failed: ok=%v len(out)=%d len(rest)=%d", len(s), ok, len(out), len(rest))
		}
	}
}

func TestParseStringRejectsTruncatedInput(t *testing.T) {
	for _, in := range [][]byte{nil, {0, 0, 0}, {0, 0, 0, 5, 'a'}, {0xff, 0xff, 0xff, 0xff}} {
		if _, _, ok := ParseString(in); ok {
			t.Errorf("expected %v to be rejected", in)
		}
	}
}
