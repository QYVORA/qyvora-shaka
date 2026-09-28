package cli

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// A run that never emits an event must not create or truncate the
// destination.
//
// The event file used to be opened as soon as the flags were resolved, which is
// before the interactive session gets a chance to refuse a machine
// destination. `--events out.jsonl` in a terminal therefore left a truncated --
// usually empty -- out.jsonl behind and an error message explaining that
// nothing would be written to it. Worse, if out.jsonl already held the events
// of an earlier run, that file was destroyed by a run that never wrote a byte.
func TestEventsFileNotCreatedUntilFirstEvent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.jsonl")

	a := &appState{eventsF: path}
	if err := a.resolveEvents(t.Context()); err != nil {
		t.Fatalf("resolving events: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("destination %s exists after resolveEvents, before any event", path)
	}

	// A run that emitted nothing must also leave the previous run's file
	// untouched, so the write has to be the thing that creates it.
	prior := []byte("{\"prior\":\"run\"}\n")
	if err := os.WriteFile(path, prior, 0o600); err != nil {
		t.Fatalf("seeding prior contents: %v", err)
	}

	// Closing without a write must not truncate what was there.
	if err := a.eventSink.(*lazyFile).Close(); err != nil {
		t.Fatalf("closing an unused sink: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading prior contents: %v", err)
	}
	if string(got) != string(prior) {
		t.Fatalf("an eventless run rewrote the destination: got %q, want %q", got, prior)
	}
}

func TestEventsFileCreatedOnFirstWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.jsonl")

	a := &appState{eventsF: path}
	if err := a.resolveEvents(t.Context()); err != nil {
		t.Fatalf("resolving events: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("destination exists before the first event")
	}

	if _, err := a.eventSink.Write([]byte("{\"n\":1}\n")); err != nil {
		t.Fatalf("writing first event: %v", err)
	}
	if err := a.eventSink.(*lazyFile).Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading events: %v", err)
	}
	if string(got) != "{\"n\":1}\n" {
		t.Fatalf("destination holds %q", got)
	}
}

// The first event can arrive from any goroutine, and two of them racing the
// open would let the second truncate the first's output.
func TestEventsFileOpenIsSerialised(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.jsonl")

	l := &lazyFile{path: path}
	const writers, each = 8, 50

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				if _, err := l.Write([]byte("0123456789\n")); err != nil {
					t.Errorf("concurrent write: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if err := l.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if want := int64(writers * each * 11); fi.Size() != want {
		t.Fatalf("destination holds %d bytes, want %d: a racing open truncated the file", fi.Size(), want)
	}
}

// A destination whose directory does not exist has to fail before the run does
// any work, not on the first event.
func TestEventsFileRejectsMissingDirectory(t *testing.T) {
	dir := t.TempDir()
	a := &appState{eventsF: filepath.Join(dir, "nope", "out.jsonl")}
	if err := a.resolveEvents(t.Context()); err == nil {
		t.Fatal("a destination under a missing directory was accepted")
	}
}

// The end-to-end path: resolve the destination, emit through the real stream,
// and confirm the bytes land in the file. The tests above drive the writer
// directly, which would still pass if the stream were wired to something else.
func TestEventsStreamReachesTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.jsonl")

	a := &appState{eventsF: path}
	if err := a.resolveEvents(t.Context()); err != nil {
		t.Fatalf("resolving events: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("destination exists before the first event")
	}

	a.eventStream.Info("run.started", map[string]any{"n": 1})
	if err := a.eventSink.(*lazyFile).Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the stream wrote nothing to the destination: %v", err)
	}
	if !strings.Contains(string(b), `"run.started"`) {
		t.Fatalf("destination does not carry the emitted event: %s", b)
	}
}
