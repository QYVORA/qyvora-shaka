package directory

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/QYVORA/qyvora-shaka/internal/transport"
)

// Simulator is an in-memory directory used for deterministic testing and
// offline review. It holds entries and answers subtree searches without any
// network I/O, so unit and integration tests never depend on live
// infrastructure.
type Simulator struct {
	BaseDN      string
	Entries     []*transport.Entry
	BindUsers   map[string]string // dn -> password; nil password disables auth check
	DefaultBase string
}

// NewSimulator returns an empty simulator.
func NewSimulator(baseDN string) *Simulator {
	return &Simulator{BaseDN: baseDN, BindUsers: map[string]string{}}
}

// Add appends an entry.
func (s *Simulator) Add(e *transport.Entry) *Simulator {
	s.Entries = append(s.Entries, e)
	return s
}

// simService adapts a Simulator to the Service interface.
type simService struct {
	sim *Simulator
}

func (s *simService) Kind() Kind { return KindSim }

func (s *simService) Describe() string { return "simulator " + s.sim.BaseDN }

func (s *simService) Ping(ctx context.Context) error { return nil }

func (s *simService) RootBaseDN() (string, error) {
	if s.sim.BaseDN != "" {
		return s.sim.BaseDN, nil
	}
	return s.sim.DefaultBase, nil
}

func (s *simService) Search(ctx context.Context, baseDN, filter string, attrs []string) ([]*transport.Entry, error) {
	res, err := s.sim.Search(ctx, baseDN, filter)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (s *simService) Close() {}

// Search implements an in-memory matching engine supporting equality,
// presence, and AND filters over the entry set. Results are returned in
// deterministic DN order.
func (s *Simulator) Search(_ context.Context, baseDN, filter string) ([]*transport.Entry, error) {
	if filter == "" {
		filter = "(objectClass=*)"
	}
	var out []*transport.Entry
	for _, e := range s.Entries {
		if baseDN != "" && !strings.HasSuffix(e.DN, baseDN) {
			continue
		}
		if matchFilter(e, filter) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DN < out[j].DN })
	return out, nil
}

// matchFilter evaluates a simple filter tree.
func matchFilter(e *transport.Entry, filter string) bool {
	f := strings.TrimSpace(filter)
	switch {
	case strings.HasPrefix(f, "(&"):
		for _, p := range groupInner(f) {
			if !matchFilter(e, p) {
				return false
			}
		}
		return true
	case strings.HasPrefix(f, "(|"):
		for _, p := range groupInner(f) {
			if matchFilter(e, p) {
				return true
			}
		}
		return false
	case strings.HasPrefix(f, "(!"):
		inner := groupInner(f)
		if len(inner) == 1 {
			return !matchFilter(e, inner[0])
		}
		return false
	}
	// Simple (attr=value) or (attr=*)
	body := strings.TrimSuffix(strings.TrimPrefix(f, "("), ")")

	// Extensible match: bitwise-AND (LDAP_MATCHING_RULE_BIT_AND).
	if i := strings.Index(body, ":1.2.840.113556.1.4.803:="); i > 0 {
		attr := body[:i]
		flag := body[i+len(":1.2.840.113556.1.4.803:="):]
		want, err := strconv.ParseUint(flag, 10, 32)
		if err != nil {
			return false
		}
		values, _ := attrValues(e, attr)
		for _, v := range values {
			got, err := strconv.ParseUint(v, 10, 32)
			if err == nil && uint32(got)&uint32(want) == uint32(want) {
				return true
			}
		}
		return false
	}

	values, _ := attrValues(e, body[:strings.IndexByte(body, '=')])
	if strings.HasSuffix(body, "=*") {
		attr := strings.TrimSuffix(body, "=*")
		_, ok := attrValues(e, attr)
		return ok
	}
	if i := strings.IndexByte(body, '='); i > 0 {
		val := body[i+1:]
		if val == "*" {
			attr := body[:i]
			_, ok := attrValues(e, attr)
			return ok
		}
		for _, v := range values {
			if equalIgnoreCase(v, val) {
				return true
			}
			// AD matches objectCategory against the schema class name of the
			// category's full DN (e.g. value "CN=Person,CN=Schema,CN=Configuration,..."
			// matches filter "objectCategory=person"). Mirror that here.
			attr := strings.ToLower(body[:i])
			if attr == "objectcategory" && categoryClassMatches(v, val) {
				return true
			}
		}
	}
	return false
}

// attrValues returns the values for an attribute using a case-insensitive key
// lookup (attribute names are case-insensitive in LDAP).
func attrValues(e *transport.Entry, attr string) ([]string, bool) {
	for k, v := range e.Attributes {
		if strings.EqualFold(k, attr) {
			return v, true
		}
	}
	return nil, false
}

// categoryClassMatches reports whether the class name of an objectCategory DN
// equals the expected name.
func categoryClassMatches(categoryDN, name string) bool {
	for _, part := range strings.Split(categoryDN, ",") {
		part = strings.TrimSpace(part)
		if strings.EqualFold(part, "CN="+name) {
			return true
		}
	}
	return false
}

// groupInner returns the top-level subfilters inside a group expression of the
// form "(&(a)(b))" / "(|(a)(b))" / "(!(a))". It correctly balances parens and
// ignores the group's own opening and closing parens.
func groupInner(f string) []string {
	inner := f[2:]                        // drop "(&" / "(|" / "(!"
	inner = strings.TrimRight(inner, " ") // tolerate trailing whitespace
	if len(inner) > 0 && inner[len(inner)-1] == ')' {
		inner = inner[:len(inner)-1] // drop the group's closing paren
	}
	var parts []string
	start := -1
	depth := 0
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '(':
			if depth == 0 {
				start = i
			}
			depth++
		case ')':
			depth--
			if depth == 0 && start >= 0 {
				parts = append(parts, inner[start:i+1])
				start = -1
			}
		}
	}
	return parts
}

func equalIgnoreCase(a, b string) bool { return strings.EqualFold(a, b) }

func (s *Simulator) String() string {
	return fmt.Sprintf("simulator(%s, %d entries)", s.BaseDN, len(s.Entries))
}
