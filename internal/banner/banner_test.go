package banner

import (
	"os"
	"strings"
	"testing"
)

// TestArtNonEmpty guards against the banner being accidentally emptied.
func TestArtNonEmpty(t *testing.T) {
	if strings.TrimSpace(Art) == "" {
		t.Fatal("Art is empty — regenerate from ascii_banner.txt")
	}
}

// TestArtMatchesCanonicalFile ensures the embedded art is byte-for-byte
// identical to the canonical ascii_banner.txt at the repository root.
func TestArtMatchesCanonicalFile(t *testing.T) {
	raw, err := os.ReadFile("../../ascii_banner.txt")
	if err != nil {
		t.Fatalf("reading canonical ascii_banner.txt: %v", err)
	}
	if string(raw) != Art {
		t.Error("Art diverges from ascii_banner.txt — regenerate internal/banner/banner.go from the canonical file")
	}
}
