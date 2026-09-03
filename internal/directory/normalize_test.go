package directory

import (
	"testing"

	"github.com/QYVORA/qyvora-shaka/internal/transport"
)

func TestNormalizeUserUACFlags(t *testing.T) {
	// UAC 4194816 = 0x400000 (DONT_REQUIRE_PREAUTH) | 512 (NORMAL_ACCOUNT).
	e := &transport.Entry{DN: "CN=kari,CN=Users,DC=corp,DC=example,DC=com", Attributes: map[string][]string{
		"sAMAccountName":     {"kari"},
		"userAccountControl": {"4194816"},
		"objectCategory":     {"CN=Person,CN=Schema,CN=Configuration,DC=corp,DC=example,DC=com"},
	}}
	u := NormalizeUser(e)
	if !u.KerberosPreAuthNotRequired {
		t.Error("DONT_REQUIRE_PREAUTH bit should set KerberosPreAuthNotRequired")
	}
	if u.PasswordNeverExpires {
		t.Error("UAC value should not set PasswordNeverExpires")
	}
	if u.Domain != "corp.example.com" {
		t.Errorf("unexpected domain %q", u.Domain)
	}
	if u.SAMAccount != "kari" {
		t.Errorf("unexpected sam %q", u.SAMAccount)
	}
}

func TestNormalizeUserNeverExpiresAndDisabled(t *testing.T) {
	// 0x10000 (DONT_EXPIRE) | 0x2 (ACCOUNTDISABLE) | 512 = 66050.
	e := &transport.Entry{DN: "CN=a,CN=Users,DC=corp,DC=com", Attributes: map[string][]string{
		"sAMAccountName":     {"a"},
		"userAccountControl": {"66050"},
	}}
	u := NormalizeUser(e)
	if !u.PasswordNeverExpires {
		t.Error("DONT_EXPIRE bit should set PasswordNeverExpires")
	}
	if u.Enabled == nil || *u.Enabled {
		t.Error("ACCOUNTDISABLE bit should yield enabled=false")
	}
}

func TestNormalizeGroupMembers(t *testing.T) {
	e := &transport.Entry{DN: "CN=G,CN=Users,DC=corp,DC=com", Attributes: map[string][]string{
		"sAMAccountName": {"G"},
		"member":         {"CN=a,CN=Users,DC=corp,DC=com", "CN=b,CN=Users,DC=corp,DC=com"},
		"groupType":      {"-2147483646"},
	}}
	g := NormalizeGroup(e)
	if !g.IsSecurity {
		t.Error("groupType present should mark security group")
	}
	if len(g.Members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(g.Members))
	}
}

func TestDomainOfExtractsDCComponents(t *testing.T) {
	got := domainOf("CN=x,DC=corp,DC=example,DC=com")
	if got != "corp.example.com" {
		t.Errorf("unexpected domain %q", got)
	}
}

func TestNormalizeTrustExternalInboundTransitive(t *testing.T) {
	e := &transport.Entry{
		DN: "CN=external.example.net,CN=System,DC=corp,DC=example,DC=com",
		Attributes: map[string][]string{
			"cn": {"external.example.net"}, "name": {"external.example.net"},
			"trustDirection": {"2"}, "trustType": {"2"}, "trustAttributes": {"0"},
		},
	}
	tr := NormalizeTrust(e)
	if tr.SourceDomain != "corp.example.com" {
		t.Errorf("unexpected source %q", tr.SourceDomain)
	}
	if tr.TargetDomain != "external.example.net" {
		t.Errorf("unexpected target %q", tr.TargetDomain)
	}
	if tr.Direction != "inbound" {
		t.Errorf("unexpected direction %q", tr.Direction)
	}
	if tr.Type != "external" {
		t.Errorf("unexpected type %q", tr.Type)
	}
	if !tr.Transitive {
		t.Error("trust with attributes 0 should be transitive")
	}
	if tr.IsSIDFiltered {
		t.Error("trust with attributes 0 should not be SID filtered")
	}
}

func TestNormalizeTrustQuarantinedIsSIDFiltered(t *testing.T) {
	e := &transport.Entry{
		DN: "CN=other.net,CN=System,DC=corp,DC=com",
		Attributes: map[string][]string{
			"cn":             {"other.net"},
			"trustDirection": {"3"}, "trustType": {"4"}, "trustAttributes": {"512"}, // 0x200 QUARANTINED
		},
	}
	tr := NormalizeTrust(e)
	if tr.Direction != "bidirectional" {
		t.Errorf("unexpected direction %q", tr.Direction)
	}
	if tr.Type != "forest" {
		t.Errorf("unexpected type %q", tr.Type)
	}
	if !tr.IsSIDFiltered {
		t.Error("QUARANTINED attribute should mark SID filtering as enabled")
	}
}

func TestNormalizeTrustNonTransitive(t *testing.T) {
	e := &transport.Entry{
		DN: "CN=leaf.net,CN=System,DC=corp,DC=com",
		Attributes: map[string][]string{
			"cn":             {"leaf.net"},
			"trustDirection": {"1"}, "trustType": {"3"}, "trustAttributes": {"1"}, // 0x1 NON_TRANSITIVE
		},
	}
	tr := NormalizeTrust(e)
	if tr.Direction != "outbound" {
		t.Errorf("unexpected direction %q", tr.Direction)
	}
	if tr.Type != "parent_child" {
		t.Errorf("unexpected type %q", tr.Type)
	}
	if tr.Transitive {
		t.Error("NON_TRANSITIVE attribute should mark trust non-transitive")
	}
}
