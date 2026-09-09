package directory

import (
	"testing"

	"github.com/QYVORA/qyvora-shaka/internal/transport"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
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

func TestNormalizeUserDelegationAndSIDHistory(t *testing.T) {
	e := &transport.Entry{DN: "CN=svc-web,CN=Users,DC=corp,DC=example,DC=com", Attributes: map[string][]string{
		"sAMAccountName":           {"svc-web"},
		"userAccountControl":       {"512"},
		"msDS-AllowedToDelegateTo": {"MSSQLSvc/sql01.corp.example.com:1433", "HTTP/web.corp.example.com"},
		"sidHistory":               {"S-1-5-21-1000000000-2000000000-3000000000-512"},
		"objectCategory":           {"CN=Person,CN=Schema,CN=Configuration,DC=corp,DC=example,DC=com"},
	}}
	u := NormalizeUser(e)
	if u.TrustedForDelegation {
		t.Error("constrained delegation (AllowedToDelegateTo) must not set the unconstrained flag")
	}
	if len(u.AllowedToDelegateTo) != 2 {
		t.Errorf("expected 2 allowed-to-delegate-to targets, got %v", u.AllowedToDelegateTo)
	}
	if len(u.SIDHistory) != 1 || u.SIDHistory[0] != "S-1-5-21-1000000000-2000000000-3000000000-512" {
		t.Errorf("unexpected SID history %v", u.SIDHistory)
	}
}

func TestNormalizeComputerDelegationLAPSAndSPNs(t *testing.T) {
	e := &transport.Entry{DN: "CN=FILESRV,CN=Computers,DC=corp,DC=example,DC=com", Attributes: map[string][]string{
		"sAMAccountName":              {"FILESRV$"},
		"userAccountControl":          {"528384"}, // 0x80000 TRUSTED_FOR_DELEGATION | 0x1000 WORKSTATION_TRUST_ACCOUNT
		"ms-Mcs-AdmPwdExpirationTime": {"133000000000000000"},
		"servicePrincipalName":        {"MSSQLSvc/filesrv.corp.example.com:1433", "CIFS/filesrv.corp.example.com"},
		"objectCategory":              {"computer"},
	}}
	c := NormalizeComputer(e)
	if !c.TrustedForDelegation {
		t.Error("TRUSTED_FOR_DELEGATION bit should set TrustedForDelegation on a computer")
	}
	if !c.LAPSManaged {
		t.Error("ms-Mcs-AdmPwdExpirationTime presence should mark LAPSManaged")
	}
	if len(c.ServicePrincipalNames) != 2 {
		t.Errorf("expected 2 computer SPNs, got %v", c.ServicePrincipalNames)
	}
}

func TestNormalizeComputerRBCDNotLAPS(t *testing.T) {
	e := &transport.Entry{DN: "CN=WEBAPP,CN=Computers,DC=corp,DC=example,DC=com", Attributes: map[string][]string{
		"sAMAccountName":                           {"WEBAPP$"},
		"userAccountControl":                       {"4096"},
		"msDS-AllowedToActOnBehalfOfOtherIdentity": {"CN=svc-web,CN=Users,DC=corp,DC=example,DC=com"},
		"objectCategory":                           {"computer"},
	}}
	c := NormalizeComputer(e)
	if c.AllowedToActOnBehalfOf != "CN=svc-web,CN=Users,DC=corp,DC=example,DC=com" {
		t.Errorf("expected RBCD principal, got %q", c.AllowedToActOnBehalfOf)
	}
	if c.LAPSManaged {
		t.Error("computer without ms-Mcs-AdmPwdExpirationTime must not be LAPSManaged")
	}
	if c.TrustedForDelegation {
		t.Error("RBCD must not imply unconstrained delegation")
	}
}

func TestNormalizeOUgPLinks(t *testing.T) {
	e := &transport.Entry{DN: "OU=Domain Controllers,DC=corp,DC=example,DC=com", Attributes: map[string][]string{
		"ou": {"Domain Controllers"}, "name": {"Domain Controllers"},
		"gPLink": {"[LDAP://CN={GUID},CN=Policies,CN=System,DC=corp,DC=example,DC=com;0][LDAP://CN={GUID2},CN=Policies,CN=System,DC=corp,DC=example,DC=com;1]"},
	}}
	ou := NormalizeOU(e)
	if len(ou.LinkedGPOs) != 2 {
		t.Fatalf("expected 2 linked GPOs from gPLink, got %v", ou.LinkedGPOs)
	}
	if ou.LinkedGPOs[0] != "CN={GUID},CN=Policies,CN=System,DC=corp,DC=example,DC=com" {
		t.Errorf("unexpected first link %q", ou.LinkedGPOs[0])
	}
}

func TestApplyDomainPasswordPolicyObserved(t *testing.T) {
	d := &models.Domain{}
	e := &transport.Entry{DN: "DC=corp,DC=com", Attributes: map[string][]string{
		"minPwdLen": {"8"}, "pwdProperties": {"1"}, "maxPwdAge": {"-36288000000000"},
	}}
	ApplyDomainPasswordPolicy(d, e)
	pp := d.PasswordPolicy
	if !pp.Observed || pp.MinLength != 8 || !pp.Complexity || pp.MaxAgeDays != 42 {
		t.Errorf("unexpected password policy %+v", pp)
	}
}

func TestApplyDomainPasswordPolicyUnobservedWhenAbsent(t *testing.T) {
	d := &models.Domain{}
	e := &transport.Entry{DN: "DC=corp,DC=com", Attributes: map[string][]string{
		"name": {"corp"},
	}}
	ApplyDomainPasswordPolicy(d, e)
	if d.PasswordPolicy.Observed {
		t.Error("password policy must stay unobserved when attributes are absent")
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
