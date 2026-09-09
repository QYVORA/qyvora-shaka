package builtin

import (
	"testing"

	"github.com/QYVORA/qyvora-shaka/internal/rules"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

func TestBuiltinCountAndIDsUnique(t *testing.T) {
	e := rules.New()
	e.AddMany(Builtin()...)
	rs := e.Rules()
	seen := map[string]bool{}
	for _, r := range rs {
		if seen[r.ID] {
			t.Fatalf("duplicate rule ID %q", r.ID)
		}
		seen[r.ID] = true
	}
	if len(rs) < 18 {
		t.Fatalf("expected at least 18 builtin rules, got %d", len(rs))
	}
}

func TestBuiltinPreAuthRuleFires(t *testing.T) {
	e := rules.New()
	e.AddMany(Builtin()...)
	ctx := rules.Context{Users: []*models.User{
		{SAMAccount: "kari", KerberosPreAuthNotRequired: true},
		{SAMAccount: "alice"},
	}}
	findings := e.Eval(ctx)
	preauth := false
	for _, f := range findings {
		if f.RuleID == "ADM-003" {
			preauth = true
			if len(f.Objects) != 1 || f.Objects[0] != "kari" {
				t.Errorf("preauth finding should target kari, got %v", f.Objects)
			}
		}
	}
	if !preauth {
		t.Fatal("ADM-003 should fire for a preauth-not-required account")
	}
}

func TestBuiltinPrivilegedMembershipFires(t *testing.T) {
	e := rules.New()
	e.AddMany(Builtin()...)
	ctx := rules.Context{Users: []*models.User{
		{SAMAccount: "svc", AdminCount: true},
	}}
	findings := e.Eval(ctx)
	adm := false
	for _, f := range findings {
		if f.RuleID == "ADM-001" {
			adm = true
		}
	}
	if !adm {
		t.Fatal("ADM-001 should fire for an adminCount account")
	}
}

func TestBuiltinDeterministic(t *testing.T) {
	e := rules.New()
	e.AddMany(Builtin()...)
	ctx := rules.Context{Users: []*models.User{
		{SAMAccount: "svc", AdminCount: true},
		{SAMAccount: "kari", KerberosPreAuthNotRequired: true},
	}}
	a := e.Eval(ctx)
	b := e.Eval(ctx)
	if len(a) != len(b) {
		t.Fatalf("determinism broken: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Fingerprint() != b[i].Fingerprint() || a[i].Title != b[i].Title {
			t.Fatalf("determinism broken at %d", i)
		}
	}
}

func TestBuiltinKerberoastableFires(t *testing.T) {
	e := rules.New()
	e.AddMany(Builtin()...)
	ctx := rules.Context{Users: []*models.User{
		{SAMAccount: "svc-sql", ServicePrincipalNames: []string{"MSSQLSvc/sql.corp.example.com:1433"}},
		{SAMAccount: "plain"},
	}}
	findings := e.Eval(ctx)
	kerb := false
	for _, f := range findings {
		if f.RuleID == "ADM-007" {
			kerb = true
			if len(f.Objects) != 1 || f.Objects[0] != "svc-sql" {
				t.Errorf("ADM-007 should target svc-sql, got %v", f.Objects)
			}
			if f.Attributes["spn_count"] != "1" {
				t.Errorf("ADM-007 spn_count should be 1, got %q", f.Attributes["spn_count"])
			}
		}
	}
	if !kerb {
		t.Fatal("ADM-007 should fire for an SPN-bearing account")
	}
}

func TestBuiltinKerberoastablePrivilegedIsHigh(t *testing.T) {
	e := rules.New()
	e.AddMany(Builtin()...)
	ctx := rules.Context{Users: []*models.User{
		{SAMAccount: "da-sql", ServicePrincipalNames: []string{"MSSQLSvc/db.corp:1433"}, AdminCount: true},
	}}
	var sev models.Severity
	for _, f := range e.Eval(ctx) {
		if f.RuleID == "ADM-007" {
			sev = f.Severity
		}
	}
	if sev != models.SeverityHigh {
		t.Fatalf("ADM-007 for privileged SPN account should be high, got %s", sev)
	}
}

func TestBuiltinConstrainedDelegationFires(t *testing.T) {
	e := rules.New()
	e.AddMany(Builtin()...)
	ctx := rules.Context{Users: []*models.User{
		{SAMAccount: "svc-web", AllowedToDelegateTo: []string{"MSSQLSvc/sql01.corp:1433"}},
		{SAMAccount: "plain"},
	}}
	findings := e.Eval(ctx)
	if n := countRule(findings, "ADM-008"); n != 1 {
		t.Fatalf("ADM-008 should fire once for constrained delegation, got %d", n)
	}
	for _, f := range findings {
		if f.RuleID == "ADM-008" {
			if f.Attributes["targets"] != "MSSQLSvc/sql01.corp:1433" {
				t.Errorf("ADM-008 should carry the delegation target, got %q", f.Attributes["targets"])
			}
		}
	}
}

func TestBuiltinConstrainedDelegationIsNotUnconstrained(t *testing.T) {
	e := rules.New()
	e.AddMany(Builtin()...)
	ctx := rules.Context{Users: []*models.User{
		{SAMAccount: "svc-web", AllowedToDelegateTo: []string{"MSSQLSvc/sql01.corp:1433"}},
	}}
	for _, f := range e.Eval(ctx) {
		if f.RuleID == "ADM-004" {
			t.Fatalf("ADM-004 must not fire for a constrained-delegation account")
		}
	}
}

func TestBuiltinComputerUnconstrainedDelegationFires(t *testing.T) {
	e := rules.New()
	e.AddMany(Builtin()...)
	ctx := rules.Context{Computers: []*models.Computer{
		{Name: "FILESRV", TrustedForDelegation: true},
		{Name: "WEB01"},
	}}
	if n := countRule(e.Eval(ctx), "ADM-009"); n != 1 {
		t.Fatalf("ADM-009 should fire once for a delegated computer, got %d", n)
	}
}

func TestBuiltinComputerRBCDAllowsFires(t *testing.T) {
	e := rules.New()
	e.AddMany(Builtin()...)
	ctx := rules.Context{Computers: []*models.Computer{
		{Name: "WEBAPP", AllowedToActOnBehalfOf: "CN=svc-web,CN=Users,DC=corp"},
	}}
	if n := countRule(e.Eval(ctx), "ADM-010"); n != 1 {
		t.Fatalf("ADM-010 should fire for an RBCD-enabled computer, got %d", n)
	}
}

func TestBuiltinRiskySPNClassFires(t *testing.T) {
	e := rules.New()
	e.AddMany(Builtin()...)
	ctx := rules.Context{
		Users: []*models.User{
			{SAMAccount: "svc-web", ServicePrincipalNames: []string{"HTTP/web.corp:443"}},
		},
		Computers: []*models.Computer{
			{Name: "FILESRV", ServicePrincipalNames: []string{"MSSQLSvc/filesrv.corp:1433"}},
			{Name: "PLAIN", ServicePrincipalNames: []string{"HOST/plain.corp"}},
		},
	}
	n := countRule(e.Eval(ctx), "ADM-011")
	if n != 2 {
		t.Fatalf("ADM-011 should fire once per risky SPN principal, got %d", n)
	}
}

func TestBuiltinCredentialInDescriptionFires(t *testing.T) {
	e := rules.New()
	e.AddMany(Builtin()...)
	ctx := rules.Context{Users: []*models.User{
		{SAMAccount: "bob", Description: "Onboarding default password1 issued"},
		{SAMAccount: "fine", Description: "Backup service account"},
	}}
	if n := countRule(e.Eval(ctx), "ADM-012"); n != 1 {
		t.Fatalf("ADM-012 should fire for credential-looking descriptions, got %d", n)
	}
}

func TestBuiltinSIDHistoryFires(t *testing.T) {
	e := rules.New()
	e.AddMany(Builtin()...)
	ctx := rules.Context{Users: []*models.User{
		{SAMAccount: "legacy", SIDHistory: []string{"S-1-5-21-1000000000-2000000000-3000000000-512"}},
		{SAMAccount: "plain"},
	}}
	if n := countRule(e.Eval(ctx), "ADM-013"); n != 1 {
		t.Fatalf("ADM-013 should fire for SID-history accounts, got %d", n)
	}
}

func TestBuiltinNestedPrivilegedMembershipFires(t *testing.T) {
	e := rules.New()
	e.AddMany(Builtin()...)
	const base = "DC=corp,DC=example,DC=com"
	ctx := rules.Context{
		Users: []*models.User{
			{SAMAccount: "monitor", DistName: "CN=Monitor Service,CN=Users," + base},
			{SAMAccount: "direct", DistName: "CN=Direct,CN=Users," + base},
		},
		Groups: []*models.Group{
			{SAMAccount: "Domain Admins", Name: "Domain Admins", DistName: "CN=Domain Admins,CN=Users," + base,
				Members: []string{"CN=IT Support,CN=Users," + base}},
			{SAMAccount: "IT Support", DistName: "CN=IT Support,CN=Users," + base,
				Members: []string{"CN=Monitor Service,CN=Users," + base}},
		},
	}
	findings := e.Eval(ctx)
	n := 0
	for _, f := range findings {
		if f.RuleID == "ADM-014" {
			n++
			if f.Objects[0] != "monitor" {
				t.Errorf("ADM-014 should target monitor, got %v", f.Objects)
			}
		}
	}
	if n != 1 {
		t.Fatalf("ADM-014 should fire once for nested privileged membership, got %d", n)
	}
}

func TestBuiltinLAPSNotAppliedFires(t *testing.T) {
	e := rules.New()
	e.AddMany(Builtin()...)
	ctx := rules.Context{Computers: []*models.Computer{
		{Name: "WEBAPP"},
		{Name: "WEB01", LAPSManaged: true},
		{Name: "DC01", DistName: "CN=DC01,OU=Domain Controllers,DC=corp"},
	}}
	if n := countRule(e.Eval(ctx), "AUTH-002"); n != 1 {
		t.Fatalf("AUTH-002 should fire only for non-DC unmanaged computers, got %d", n)
	}
}

func TestBuiltinPrivilegedGPOLinkFires(t *testing.T) {
	e := rules.New()
	e.AddMany(Builtin()...)
	ctx := rules.Context{OUs: []*models.OrganizationalUnit{
		{Name: "Domain Controllers", DistName: "OU=Domain Controllers,DC=corp",
			LinkedGPOs: []string{"CN={GUID},CN=Policies,CN=System,DC=corp"}},
		{Name: "IT", DistName: "OU=IT,DC=corp",
			LinkedGPOs: []string{"CN={GUID2},CN=Policies,CN=System,DC=corp"}},
	}}
	if n := countRule(e.Eval(ctx), "AUTH-003"); n != 1 {
		t.Fatalf("AUTH-003 should fire only for privileged containers, got %d", n)
	}
}

func TestBuiltinWeakPasswordPolicyFires(t *testing.T) {
	e := rules.New()
	e.AddMany(Builtin()...)
	ctx := rules.Context{Domains: []*models.Domain{
		{Name: "corp.example.com", PasswordPolicy: models.PasswordPolicy{
			Observed: true, MinLength: 8, Complexity: true, MaxAgeDays: 42,
		}},
		{Name: "clean.example.com", PasswordPolicy: models.PasswordPolicy{
			Observed: true, MinLength: 15, Complexity: true,
		}},
		{Name: "unknown.example.com"},
	}}
	n := countRule(e.Eval(ctx), "AUTH-004")
	if n != 1 {
		t.Fatalf("AUTH-004 should fire only for observed weak policies, got %d", n)
	}
}

func countRule(findings []*models.Finding, ruleID string) int {
	n := 0
	for _, f := range findings {
		if f.RuleID == ruleID {
			n++
		}
	}
	return n
}
