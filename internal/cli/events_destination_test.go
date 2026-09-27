package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-shaka/internal/logger"
	"github.com/QYVORA/qyvora-shaka/internal/output"
)

// disableSpec is every spelling that must turn the event stream off.
var disableSpec = []string{"", "off", "none", "disable", "disabled", "OFF", "Disable", "DISABLED"}

// TestEventsDisableWordsCreateNoFile is a regression test.
//
// --events previously treated any unrecognised value as a file path, so the
// documented way to disable the stream ("--events off") created a file
// literally named "off" in the working directory and still printed the
// stream. Both halves of that are asserted here: no file, and no stream.
func openSink(t *testing.T, spec string) io.Writer {
	t.Helper()
	a := &appState{eventsF: spec, printer: output.New(), log: logger.New()}
	if err := a.resolveEvents(context.Background()); err != nil {
		t.Fatalf("resolving %q: %v", spec, err)
	}
	return a.eventSink
}

func TestEventsDisableWordsCreateNoFile(t *testing.T) {
	for _, spec := range disableSpec {
		t.Run("spec="+spec, func(t *testing.T) {
			dir := t.TempDir()
			chdir(t, dir)

			sink := openSink(t, spec)
			if sink != nil {
				t.Fatalf("--events %q must yield no stream, got a writer", spec)
			}

			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				names := make([]string, 0, len(entries))
				for _, e := range entries {
					names = append(names, e.Name())
				}
				t.Fatalf("--events %q created %v; a disable word must create nothing", spec, names)
			}
		})
	}
}

// TestEventsFileIsTruncatedNotAppended pins one file per run.
//
// Four frameworks appended and four truncated, so a consumer tailing the
// file could not tell where one run ended and the next began.
func TestEventsFileIsTruncatedNotAppended(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	path := filepath.Join(dir, "run.jsonl")

	if err := os.WriteFile(path, []byte("PREVIOUS RUN\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sink := openSink(t, path)
	if sink == nil {
		t.Fatal("a file path must yield a stream")
	}
	if _, err := sink.Write([]byte("CURRENT RUN\n")); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "PREVIOUS RUN") {
		t.Fatal("the events file was appended to; it must be truncated so one file holds one run")
	}
	if !strings.Contains(string(b), "CURRENT RUN") {
		t.Fatal("the current run's events are missing from the file")
	}
}

// TestEventsStreamWordsCreateNoFile checks the two fixed destinations never
// touch the filesystem.
func TestEventsStreamWordsCreateNoFile(t *testing.T) {
	for _, spec := range []string{"stdout", "stderr", "STDOUT", "Stderr"} {
		t.Run("spec="+spec, func(t *testing.T) {
			dir := t.TempDir()
			chdir(t, dir)
			if sink := openSink(t, spec); sink == nil {
				t.Fatalf("--events %q must yield a stream", spec)
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Fatalf("--events %q created a file; it names a fixed stream", spec)
			}
		})
	}
}

// chdir moves into dir for the duration of the test. Resolving a spec to a
// file path is relative to the working directory, so that is what has to be
// controlled to observe the "off" file being created.
func chdir(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
}
