package selfupdate

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// hashBytes returns the lowercase hex SHA-256 of data.
func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// verifyChecksumManifest parses a SHA-256 manifest (checksums.txt-style) and returns the
// expected digest for artifactName. It returns an *UpdateError when the
// artifact is absent from the manifest.
func verifyChecksumManifest(manifest []byte, artifactName string, data []byte) error {
	var expected string
	sc := bufio.NewScanner(strings.NewReader(string(manifest)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if strings.TrimPrefix(fields[1], "*") == artifactName {
			expected = strings.ToLower(fields[0])
			break
		}
	}
	if expected == "" {
		return upErr(KindVerificationUnavailable,
			"release does not publish a checksum for "+artifactName, nil)
	}
	actual := hashBytes(data)
	if actual != expected {
		return upErr(KindChecksumMismatch,
			"expected "+expected+" got "+actual, nil)
	}
	return nil
}
