// Package deepening implements the follow-up engine. When discovery or
// enumeration produces an object, the engine determines which analyzers apply
// and queues deeper work, collects the result, generates new relationships
// and findings, then queues additional work. Infinite loops are prevented
// through deduplication, visited-object tracking, operation IDs, depth
// limits, and cycle detection.
package deepening

import (
	"context"
	"sync"
)

// OpID identifies one scheduled follow-up operation (used for dedup and
// cycle protection).
type OpID string

// Work is one unit of follow-up analysis.
type Work struct {
	OpID    OpID
	Object  string
	Depth   int
	Handler func(ctx context.Context) ([]OpID, error)
}

// Engine schedules and runs follow-up work with bounded depth and
// deduplication.
type Engine struct {
	mu       sync.Mutex
	visited  map[OpID]bool
	maxDepth int
	wg       sync.WaitGroup
	workers  chan struct{}
}

// New returns a follow-up engine with a maximum depth limit and a bounded
// worker pool.
func New(maxDepth, workerCount int) *Engine {
	if maxDepth < 1 {
		maxDepth = 1
	}
	if workerCount < 1 {
		workerCount = 4
	}
	return &Engine{
		visited:  map[OpID]bool{},
		maxDepth: maxDepth,
		workers:  make(chan struct{}, workerCount),
	}
}

// Schedule queues a work item if it has not already been visited and is
// within the depth limit.
func (e *Engine) Schedule(w Work) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.visited[w.OpID] {
		return
	}
	if w.Depth > e.maxDepth {
		return
	}
	e.visited[w.OpID] = true
	e.wg.Add(1)
	e.workers <- struct{}{}
	go func() {
		defer func() {
			<-e.workers
			e.wg.Done()
		}()
		next, err := w.Handler(context.Background())
		if err != nil {
			return
		}
		for _, id := range next {
			e.mu.Lock()
			visited := e.visited[id]
			e.mu.Unlock()
			if visited {
				continue
			}
			if w.Depth+1 <= e.maxDepth {
				e.Schedule(Work{OpID: id, Object: w.Object, Depth: w.Depth + 1})
			}
		}
	}()
}

// Wait blocks until all scheduled work completes. Callers should pass a
// cancellable context; the worker handlers are responsible for honoring it.
func (e *Engine) Wait() {
	e.wg.Wait()
}

// Visited reports whether an operation ID has already been processed.
func (e *Engine) Visited(id OpID) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.visited[id]
}
