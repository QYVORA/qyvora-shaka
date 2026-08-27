package selfupdate

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
)

// hashBytes returns the lowercase hex SHA-256 of data.
func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// verifyChecksumManifest parses a SHA256SUMS-style manifest and returns the
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

// hashReader computes the SHA-256 of r while copying to dst. It returns the
// hex digest.
func hashReader(dst io.Writer, r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(dst, h), r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
