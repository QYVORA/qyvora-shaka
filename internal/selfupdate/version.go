package selfupdate

import (
	"strconv"
	"strings"
)

// CompareVersions compares two release versions and returns -1, 0 or 1.
// It implements numeric semantic-version comparison (v1.10.0 sorts after
// v1.9.0), tolerates an optional leading "v", ignores build metadata, and
// applies prerelease ordering.
func CompareVersions(a, b string) int {
	pa := parseVersion(a)
	pb := parseVersion(b)
	for i := 0; i < len(pa.core) || i < len(pb.core); i++ {
		var sa, sb int
		if i < len(pa.core) {
			sa = pa.core[i]
		}
		if i < len(pb.core) {
			sb = pb.core[i]
		}
		switch {
		case sa < sb:
			return -1
		case sa > sb:
			return 1
		}
	}
	switch {
	case pa.pre == "" && pb.pre != "":
		return 1
	case pa.pre != "" && pb.pre == "":
		return -1
	case pa.pre == pb.pre:
		return 0
	}
	return comparePrerelease(pa.pre, pb.pre)
}

type versionParts struct {
	core []int
	pre  string
}

func parseVersion(v string) versionParts {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	parts := versionParts{}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		parts.pre = v[i+1:]
		v = v[:i]
	}
	for _, seg := range strings.Split(v, ".") {
		n, err := strconv.Atoi(strings.TrimSpace(seg))
		if err != nil {
			n = 0
		}
		parts.core = append(parts.core, n)
	}
	if parts.core == nil {
		parts.core = []int{0}
	}
	return parts
}

func comparePrerelease(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var sa, sb string
		if i < len(as) {
			sa = as[i]
		}
		if i < len(bs) {
			sb = bs[i]
		}
		if sa == sb {
			continue
		}
		ca, aIsNum := strconv.Atoi(sa)
		cb, bIsNum := strconv.Atoi(sb)
		switch {
		case aIsNum == nil && bIsNum == nil && ca != cb:
			if ca < cb {
				return -1
			}
			return 1
		case aIsNum == nil && bIsNum != nil:
			return -1
		case aIsNum != nil && bIsNum == nil:
			return 1
		}
		// numeric vs numeric handled above; alphanumeric strings compare
		// lexically (ASCII order per semver).
		if sa < sb {
			return -1
		}
		return 1
	}
	if len(as) < len(bs) {
		return -1
	}
	if len(as) > len(bs) {
		return 1
	}
	return 0
}

// isDev reports whether a version string carries no release identity.
func isDev(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "dev", "unknown", "none", "(devel)":
		return true
	}
	return false
}
