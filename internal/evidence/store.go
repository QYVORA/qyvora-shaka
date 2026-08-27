// Package evidence provides the assessment evidence store. Every meaningful
// finding is backed by evidence; evidence is immutable once recorded within a
// session. Reporting traces finding → evidence → observed object →
// collection source.
package evidence

import (
	"sync"
	"time"

	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// Store accumulates evidence records with hash-based deduplication. It is
// safe for concurrent use so parallel enumeration can record evidence.
type Store struct {
	mu    sync.Mutex
	items []*models.Evidence
}

// New returns an empty evidence store.
func New() *Store { return &Store{} }

// Add records an evidence item, deduplicating by content hash. It returns the
// stored item.
func (s *Store) Add(ev *models.Evidence) *models.Evidence {
	if ev == nil {
		return nil
	}
	if ev.ID == "" {
		ev.ID = models.NewID("ev")
	}
	if ev.Hash == "" {
		ev.Hash = models.HashContent(ev.Data)
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.items {
		if existing.Hash == ev.Hash {
			return existing
		}
	}
	s.items = append(s.items, ev)
	return ev
}

// All returns all stored evidence in insertion order.
func (s *Store) All() []*models.Evidence {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*models.Evidence, len(s.items))
	copy(out, s.items)
	return out
}
