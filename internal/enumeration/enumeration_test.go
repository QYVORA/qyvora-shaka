package enumeration

import (
	"context"
	"testing"

	"github.com/QYVORA/qyvora-shaka/internal/directory"
)

func TestUserEnumeratorDemo(t *testing.T) {
	svc := demoService(t)
	ue := UserEnumerator{Dir: svc}
	users, err := ue.Enumerate(context.Background(), baseDN(t, svc), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 8 {
		t.Fatalf("expected 8 users, got %d", len(users))
	}
}

func TestGroupEnumeratorDemo(t *testing.T) {
	svc := demoService(t)
	ge := GroupEnumerator{Dir: svc}
	groups, err := ge.Enumerate(context.Background(), baseDN(t, svc), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 4 {
		t.Fatalf("expected 4 groups, got %d", len(groups))
	}
}

func TestComputerEnumeratorDemo(t *testing.T) {
	svc := demoService(t)
	ce := ComputerEnumerator{Dir: svc}
	comps, err := ce.Enumerate(context.Background(), baseDN(t, svc), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 4 {
		t.Fatalf("expected 4 computers, got %d", len(comps))
	}
}

func TestTrustEnumeratorDemo(t *testing.T) {
	svc := demoService(t)
	te := TrustEnumerator{Dir: svc}
	trusts, err := te.Enumerate(context.Background(), baseDN(t, svc), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(trusts) != 1 {
		t.Fatalf("expected 1 trust, got %d", len(trusts))
	}
	tr := trusts[0]
	if tr.SourceDomain != "corp.example.com" {
		t.Errorf("unexpected source %q", tr.SourceDomain)
	}
	if tr.TargetDomain != "external.example.net" {
		t.Errorf("unexpected target %q", tr.TargetDomain)
	}
	if tr.Type != "external" {
		t.Errorf("unexpected type %q", tr.Type)
	}
	if tr.Direction != "inbound" {
		t.Errorf("unexpected direction %q", tr.Direction)
	}
	if !tr.Transitive {
		t.Error("trust should be transitive")
	}
	if tr.IsSIDFiltered {
		t.Error("trust should not be SID filtered")
	}
}

func TestTrustEnumeratorLimit(t *testing.T) {
	svc := demoService(t)
	te := TrustEnumerator{Dir: svc}
	trusts, err := te.Enumerate(context.Background(), baseDN(t, svc), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(trusts) > 1 {
		t.Fatalf("demo should have at most 1 trust, got %d", len(trusts))
	}
}

func TestGPOEnumeratorDemo(t *testing.T) {
	svc := demoService(t)
	ge := GPOEnumerator{Dir: svc}
	gpos, err := ge.Enumerate(context.Background(), baseDN(t, svc), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(gpos) != 2 {
		t.Fatalf("expected 2 GPOs, got %d", len(gpos))
	}
}

func demoService(t *testing.T) directory.Service {
	t.Helper()
	sim := directory.Demo()
	svc, err := directory.New(context.Background(), directory.Options{Sim: sim})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func baseDN(t *testing.T, svc directory.Service) string {
	t.Helper()
	dn, err := svc.RootBaseDN()
	if err != nil {
		t.Fatal(err)
	}
	return dn
}
