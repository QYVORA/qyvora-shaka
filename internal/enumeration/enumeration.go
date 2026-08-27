// Package enumeration operates on discovered objects. Enumeration is not one
// enormous function: focused enumerators (UserEnumerator, GroupEnumerator,
// ComputerEnumerator, OUEnumerator, TrustEnumerator, PolicyEnumerator) each
// receive a structured target, collect relevant information, validate and
// normalize it, attach evidence, emit events, and return structured results.
package enumeration

import (
	"context"
	"sort"

	"github.com/QYVORA/qyvora-shaka/internal/directory"
	"github.com/QYVORA/qyvora-shaka/internal/events"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// Result aggregates everything one enumeration pass discovered.
type Result struct {
	Users     []*models.User
	Groups    []*models.Group
	Computers []*models.Computer
	OUs       []*models.OrganizationalUnit
	GPOs      []*models.GroupPolicy
	Trusts    []*models.Trust
}

// UserEnumerator enumerates user objects.
type UserEnumerator struct {
	Dir    directory.Service
	Events *events.Stream
}

// Enumerate returns all users in the base, normalizing each entry.
func (u *UserEnumerator) Enumerate(ctx context.Context, base string, limit int) ([]*models.User, error) {
	entries, err := u.Dir.Search(ctx, base, "(&(objectCategory=person)(objectClass=user))",
		[]string{"cn", "name", "sAMAccountName", "userPrincipalName", "distinguishedName",
			"description", "userAccountControl", "adminCount", "servicePrincipalName",
			"lastLogonTimestamp", "msDS-AllowedToDelegateTo"})
	if err != nil {
		return nil, err
	}
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}
	var out []*models.User
	for _, e := range entries {
		user := directory.NormalizeUser(e)
		out = append(out, user)
		if u.Events != nil {
			u.Events.Info(events.UserDiscovered, map[string]any{
				"sam": user.SAMAccount, "upn": user.UPN, "dn": user.DistName,
			})
		}
	}
	return out, nil
}

// GroupEnumerator enumerates group objects.
type GroupEnumerator struct {
	Dir    directory.Service
	Events *events.Stream
}

// Enumerate lists all security/distribution groups.
func (g *GroupEnumerator) Enumerate(ctx context.Context, base string, limit int) ([]*models.Group, error) {
	entries, err := g.Dir.Search(ctx, base, "(&(objectCategory=group))",
		[]string{"cn", "name", "sAMAccountName", "distinguishedName", "description", "groupType", "adminCount", "member"})
	if err != nil {
		return nil, err
	}
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}
	var out []*models.Group
	for _, e := range entries {
		grp := directory.NormalizeGroup(e)
		out = append(out, grp)
		if g.Events != nil {
			g.Events.Info(events.GroupDiscovered, map[string]any{
				"sam": grp.SAMAccount, "dn": grp.DistName,
			})
		}
	}
	return out, nil
}

// GroupMembers expands one group's direct + nested members (deduplicated).
func (g *GroupEnumerator) Members(ctx context.Context, base, groupDN string, maxDepth int) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	var walk func(dn string, depth int) error
	walk = func(dn string, depth int) error {
		if seen[dn] || depth > maxDepth {
			return nil
		}
		seen[dn] = true
		out = append(out, dn)
		entries, err := g.Dir.Search(ctx, base, "(&(distinguishedName="+escapeDN(dn)+"))",
			[]string{"member"})
		if err != nil {
			return nil
		}
		for _, e := range entries {
			for _, m := range e.Attributes["member"] {
				if err := walk(m, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(groupDN, 0); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// ComputerEnumerator enumerates computer objects.
type ComputerEnumerator struct {
	Dir    directory.Service
	Events *events.Stream
}

func (c *ComputerEnumerator) Enumerate(ctx context.Context, base string, limit int) ([]*models.Computer, error) {
	entries, err := c.Dir.Search(ctx, base, "(objectCategory=computer)",
		[]string{"cn", "name", "distinguishedName", "operatingSystem", "operatingSystemVersion",
			"dNSHostName", "ipv4Address", "userAccountControl", "lastLogonTimestamp"})
	if err != nil {
		return nil, err
	}
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}
	var out []*models.Computer
	for _, e := range entries {
		comp := directory.NormalizeComputer(e)
		out = append(out, comp)
		if c.Events != nil {
			c.Events.Info(events.ComputerDiscovered, map[string]any{
				"name": comp.Name, "dn": comp.DistName, "os": comp.OperatingSystem,
			})
		}
	}
	return out, nil
}

// OUEnumerator enumerates organizational units.
type OUEnumerator struct {
	Dir    directory.Service
	Events *events.Stream
}

func (o *OUEnumerator) Enumerate(ctx context.Context, base string, limit int) ([]*models.OrganizationalUnit, error) {
	entries, err := o.Dir.Search(ctx, base, "(objectCategory=organizationalUnit)",
		[]string{"cn", "name", "ou", "distinguishedName"})
	if err != nil {
		return nil, err
	}
	var out []*models.OrganizationalUnit
	for _, e := range entries {
		if limit > 0 && len(out) >= limit {
			break
		}
		ou := directory.NormalizeOU(e)
		out = append(out, ou)
		if o.Events != nil {
			o.Events.Info(events.OUDiscovered, map[string]any{"dn": ou.DistName})
		}
	}
	return out, nil
}

// TrustEnumerator enumerates trust objects (managed by the trust subsystem,
// but exposed here for parity).
type TrustEnumerator struct {
	Dir    directory.Service
	Events *events.Stream
}

// Helpers --------------------------------------------------------------------

func escapeDN(dn string) string {
	return dn
}
