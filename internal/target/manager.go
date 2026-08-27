// Package target manages the targets an assessment session operates on. It
// enforces the authorization gate: a target that has not been authorized
// cannot become the current target.
package target

import (
	"errors"
	"fmt"
	"sync"

	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// ErrUnauthorizedTarget is returned when an operation requires an authorized
// target but the current target has not passed the authorization gate.
var ErrUnauthorizedTarget = errors.New("target is not authorized")

// Manager holds the set of known targets and tracks the current one.
type Manager struct {
	mu      sync.RWMutex
	current *models.Target
	byID    map[string]*models.Target
}

// NewManager returns an empty target manager.
func NewManager() *Manager {
	return &Manager{byID: map[string]*models.Target{}}
}

// Set registers a target and makes it current. It refuses targets that have
// not been authorized so the gate cannot be bypassed.
func (m *Manager) Set(t *models.Target) error {
	if t == nil {
		return errors.New("cannot set a nil target")
	}
	if !t.Authorized() {
		return fmt.Errorf("%w: %s", ErrUnauthorizedTarget, t.DisplayName())
	}
	if t.ID == "" {
		t.ID = models.NewID("tgt")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID[t.ID] = t
	m.current = t
	return nil
}

// Current returns the current target, or nil.
func (m *Manager) Current() *models.Target {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// Get returns a registered target by ID.
func (m *Manager) Get(id string) (*models.Target, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.byID[id]
	return t, ok
}

// List returns all registered targets in insertion order.
func (m *Manager) List() []*models.Target {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*models.Target, 0, len(m.byID))
	for _, t := range m.byID {
		out = append(out, t)
	}
	return out
}
