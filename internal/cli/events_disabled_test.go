package cli

import "testing"

// The interactive guard and the event plumbing both ask eventsDisabled, so the two must
// never disagree about what counts as a destination. A value that turns the
// stream off has to read as "no stream", or an ordinary interactive run gets
// refused for asking for nothing.
func TestEventsDisabled(t *testing.T) {
	for _, spec := range []string{"", "off", "OFF", "none", "disable", "disabled", "Off"} {
		if !eventsDisabled(spec) {
			t.Errorf("eventsDisabled(%q) = false, want true", spec)
		}
	}
	for _, spec := range []string{"stdout", "stderr", "session.jsonl", "off.jsonl", "none.log"} {
		if eventsDisabled(spec) {
			t.Errorf("eventsDisabled(%q) = true, want false", spec)
		}
	}
}
