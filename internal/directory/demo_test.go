package directory

import (
	"context"
	"testing"

	"github.com/QYVORA/qyvora-shaka/internal/transport"
)

func TestMatchFilter(t *testing.T) {
	e := &transport.Entry{DN: "CN=Administrator,DC=corp,DC=example,DC=com", Attributes: map[string][]string{
		"objectCategory": {"CN=Person,CN=Schema,CN=Configuration,DC=corp,DC=example,DC=com"},
		"objectClass":    {"user", "person", "top"},
		"sAMAccountName": {"Administrator"},
	}}
	cases := []struct {
		f   string
		exp bool
	}{
		{"(objectClass=*)", true},
		{"(sAMAccountName=Administrator)", true},
		{"(sAMAccountName=admin)", false},
		{"(&(objectCategory=person)(objectClass=user))", true},
		{"(&(objectCategory=group))", false},
		{"(objectCategory=person)", true},
		{"(!(objectClass=computer))", true},
	}
	for _, c := range cases {
		if got := matchFilter(e, c.f); got != c.exp {
			t.Errorf("filter %q: got %v want %v", c.f, got, c.exp)
		}
	}

	dc := &transport.Entry{DN: "CN=DC01,...", Attributes: map[string][]string{
		"userAccountControl": {"532480"},
		"objectCategory":     {"computer"},
	}}
	for _, c := range []struct {
		f   string
		exp bool
	}{
		{"(userAccountControl:1.2.840.113556.1.4.803:=8192)", true},
		{"(userAccountControl:1.2.840.113556.1.4.803:=4096)", false},
	} {
		if got := matchFilter(dc, c.f); got != c.exp {
			t.Errorf("filter %q: got %v want %v", c.f, got, c.exp)
		}
	}
}

func TestDemoFixtures(t *testing.T) {
	sim := Demo()
	if len(sim.Entries) == 0 {
		t.Fatal("demo simulator has no entries")
	}
	base, _ := (&simService{sim: sim}).RootBaseDN()
	if base != "DC=corp,DC=example,DC=com" {
		t.Fatalf("unexpected base %q", base)
	}
	counts := map[string]int{
		"(&(objectCategory=person)(objectClass=user))": 4,
		"(&(objectCategory=group))":                    3,
		"(objectCategory=computer)":                    1,
		"(objectCategory=organizationalUnit)":          2,
	}
	for filter, want := range counts {
		entries, err := sim.Search(context.Background(), base, filter)
		if err != nil {
			t.Fatalf("search %q: %v", filter, err)
		}
		if len(entries) != want {
			t.Errorf("filter %q: got %d entries want %d", filter, len(entries), want)
		}
	}
}
