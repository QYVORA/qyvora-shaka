package ldap

import (
	"testing"
)

func TestAppendTagShortAndLongLength(t *testing.T) {
	if got := appendTag(0x04, []byte("hi")); string(got) != string([]byte{0x04, 0x02, 'h', 'i'}) {
		t.Errorf("short length encoding wrong: % x", got)
	}
	long := make([]byte, 0x88)
	got := appendTag(0x30, long)
	if got[0] != 0x30 || got[1] != 0x81 || got[2] != 0x88 {
		t.Errorf("long length encoding wrong: % x", got)
	}
}

func TestDecodeIntAndNegativeRejection(t *testing.T) {
	if v, err := decodeInt([]byte{0x05}); err != nil || v != 5 {
		t.Errorf("decodeInt(5) = %d, %v", v, err)
	}
	if _, err := decodeInt([]byte{0x85, 0x01}); err == nil {
		t.Error("negative integer should error")
	}
}

func TestParseFilterEquality(t *testing.T) {
	c := &Client{}
	b, err := c.filterBytes([]byte("(cn=Alice)"))
	if err != nil {
		t.Fatalf("filterBytes error: %v", err)
	}
	// Expect SEQUENCE { SearchRequest } ... but filterBytes is internal; here
	// we only assert the top filter tag is an LDAPMessage wrapping is not the
	// right shape. Instead assert it starts with the equality filter tag a3.
	if len(b) == 0 || b[0] != filterEq {
		t.Errorf("expected equality filter tag 0xa3, got % x", b)
	}
}

func TestParseFilterPresent(t *testing.T) {
	c := &Client{}
	b, err := c.filterBytes([]byte("(objectClass=*)"))
	if err != nil {
		t.Fatalf("filterBytes error: %v", err)
	}
	if b[0] != filterPresent {
		t.Errorf("expected present filter tag 0x87, got % x", b)
	}
}

func TestParseFilterAnd(t *testing.T) {
	c := &Client{}
	b, err := c.filterBytes([]byte("(&(a=b)(c=d))"))
	if err != nil {
		t.Fatalf("filterBytes error: %v", err)
	}
	if b[0] != filterAnd {
		t.Errorf("expected and filter tag 0xa0, got % x", b)
	}
}

func TestParseFilterMalformedSimple(t *testing.T) {
	c := &Client{}
	if _, err := c.filterBytes([]byte("(abcdef)")); err == nil {
		t.Error("a simple filter without '=' should error")
	}
	if _, err := c.filterBytes([]byte("")); err == nil {
		t.Error("an empty filter should error")
	}
}
