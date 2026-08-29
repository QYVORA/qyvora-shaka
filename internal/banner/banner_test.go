package banner

import (
	"strings"
	"testing"
)

// TestArtNonEmpty guards against the banner being accidentally emptied.
func TestArtNonEmpty(t *testing.T) {
	if strings.TrimSpace(Art) == "" {
		t.Fatal("Art is empty")
	}
}
