package session

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(filepath.Join(dir, "sessions"))
	if s.Dir() == "" {
		t.Fatal("Dir() should return the configured dir")
	}

	tgt := &models.Target{ID: "tgt-1", Name: "demo", Profile: "standard"}
	sess := Begin(tgt)
	if sess.TargetID != "tgt-1" || sess.Profile != "standard" {
		t.Fatalf("Begin did not bind target: %+v", sess)
	}
	sess.Users = []*models.User{{ID: "user-1", SAMAccount: "alice"}}
	Finished(sess)

	path, err := s.Save(sess)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("saved file missing: %v", err)
	}

	got, err := s.Load(sess.ID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.ID != sess.ID || len(got.Users) != 1 || got.Users[0].SAMAccount != "alice" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.End.IsZero() {
		t.Fatal("Finished should set End")
	}

	ids, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(ids) != 1 || ids[0] != sess.ID {
		t.Fatalf("List unexpected: %v", ids)
	}
}

func TestSaveNilSession(t *testing.T) {
	s := NewStore(t.TempDir())
	if _, err := s.Save(nil); err == nil {
		t.Fatal("saving nil session should error")
	}
}
