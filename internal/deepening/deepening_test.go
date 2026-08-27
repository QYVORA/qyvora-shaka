package deepening

import (
	"context"
	"sync"
	"testing"
)

func TestScheduleDedupsAndTracksVisited(t *testing.T) {
	e := New(2, 2)
	var ran int
	var mu sync.Mutex
	handler := func(context.Context) ([]OpID, error) {
		mu.Lock()
		ran++
		mu.Unlock()
		return nil, nil
	}
	e.Schedule(Work{OpID: "root", Depth: 0, Handler: handler})
	e.Schedule(Work{OpID: "root", Depth: 0, Handler: handler}) // duplicate
	e.Wait()
	if ran != 1 {
		t.Fatalf("duplicate op should run once, got %d", ran)
	}
	if !e.Visited("root") {
		t.Fatal("root op should be marked visited")
	}
}

func TestDepthLimitPreventsScheduling(t *testing.T) {
	e := New(1, 2)
	e.Schedule(Work{OpID: "deep", Depth: 5, Handler: func(context.Context) ([]OpID, error) { return nil, nil }})
	if e.Visited("deep") {
		t.Fatal("work beyond max depth must not be scheduled")
	}
}
