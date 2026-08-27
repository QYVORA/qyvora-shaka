package evidence

import (
	"testing"

	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

func TestStoreAddDedupsByHash(t *testing.T) {
	s := New()
	a := s.Add(&models.Evidence{Data: "same content"})
	b := s.Add(&models.Evidence{Data: "same content"})
	c := s.Add(&models.Evidence{Data: "different"})
	if a == nil || a.Hash == "" {
		t.Fatal("expected hash to be populated")
	}
	if b != a {
		t.Fatal("duplicate content should return the stored item")
	}
	if c == b {
		t.Fatal("different content should yield a new item")
	}
	if got := len(s.All()); got != 2 {
		t.Fatalf("expected 2 distinct evidence, got %d", got)
	}
}

func TestStoreNil(t *testing.T) {
	s := New()
	if s.Add(nil) != nil {
		t.Fatal("nil evidence should return nil")
	}
}
