package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"
)

// archiveKind classifies a release asset by its file extension.
type archiveKind int

const (
	archiveNone archiveKind = iota
	archiveTarGz
	archiveZip
)

func classifyArchive(name string) archiveKind {
	switch {
	case strings.HasSuffix(name, ".tar.gz"), strings.HasSuffix(name, ".tgz"):
		return archiveTarGz
	case strings.HasSuffix(name, ".zip"):
		return archiveZip
	default:
		return archiveNone
	}
}

// extractBinary returns the single executable entry from a release archive.
// A non-archive artifact is returned unchanged. Only the exact entry name
// "{tool}" (or "{tool}.exe" for a zip) is accepted; symlinks, directories and
// path separators are rejected outright, which structurally rules out
// traversal.
func extractBinary(data []byte, artifact, tool string) ([]byte, error) {
	switch classifyArchive(artifact) {
	case archiveTarGz:
		return extractTarGz(data, entryName(artifact, tool))
	case archiveZip:
		return extractZip(data, entryName(artifact, tool))
	default:
		return data, nil
	}
}

func entryName(artifact, tool string) string {
	if strings.HasSuffix(artifact, ".zip") {
		return tool + ".exe"
	}
	return tool
}

func extractTarGz(data []byte, entry string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("release artifact is not valid gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("release artifact is not a valid tar: %w", err)
		}
		if normalizeEntry(hdr.Name) != entry {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("archive entry %q is not a regular file", entry)
		}
		return readCapped(tr, entry)
	}
	return nil, fmt.Errorf("release archive contains no entry %q", entry)
}

func extractZip(data []byte, entry string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("release artifact is not a valid zip: %w", err)
	}
	for _, zf := range zr.File {
		if normalizeEntry(zf.Name) != entry {
			continue
		}
		if zf.Mode()&os.ModeType != 0 {
			return nil, fmt.Errorf("archive entry %q is not a regular file", entry)
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, err
		}
		defer func() { _ = rc.Close() }()
		return readCapped(rc, entry)
	}
	return nil, fmt.Errorf("release archive contains no entry %q", entry)
}

func readCapped(r io.Reader, label string) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxArtifactSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxArtifactSize {
		return nil, fmt.Errorf("archive entry %q exceeds the %d MiB safety limit", label, maxArtifactSize>>20)
	}
	return b, nil
}

// normalizeEntry reduces harmless spellings ("./bin", "/bin") to their base
// form so the exact-name comparison cannot be evaded. Multi-component names
// such as "sub/dir/bin" do NOT normalize to "bin"; they simply do not match.
func normalizeEntry(name string) string {
	name = strings.TrimPrefix(name, "/")
	for strings.HasPrefix(name, "./") {
		name = name[2:]
	}
	return name
}
