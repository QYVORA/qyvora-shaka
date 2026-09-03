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
	if len(rs) < 7 {
		t.Fatalf("expected at least 7 builtin rules, got %d", len(rs))
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
