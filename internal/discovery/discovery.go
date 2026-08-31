// Package discovery identifies the authorized environment and builds the
// initial model: domains, domain controllers, and the directory's structure.
// Discovery produces structured objects (not terminal strings), and each
// result can schedule follow-up enumeration.
package discovery

import (
	"context"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-shaka/internal/directory"
	"github.com/QYVORA/qyvora-shaka/internal/events"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// Result is the structured output of a discovery run.
type Result struct {
	Domains []*models.Domain
	DCS     []*models.DomainController
	BaseDN  string
}

// Engine discovers the authorized environment against a directory service.
type Engine struct {
	Dir    directory.Service
	Events *events.Stream
}

// DiscoverDomains discovers the domain model and default base DN.
func (e *Engine) DiscoverDomains(_ context.Context) ([]*models.Domain, string, error) {
	base, err := e.Dir.RootBaseDN()
	if err != nil {
		return nil, "", err
	}

	d := &models.Domain{
		ID:           models.NewID("domain"),
		Name:         domainFromBase(base),
		NetBIOS:      "",
		BaseDN:       base,
		State:        models.StateObserved,
		DiscoveredAt: now(),
	}
	domains := []*models.Domain{d}
	e.emitDomain(d)
	return domains, base, nil
}

// DiscoverControllers finds domain controllers via the directory.
func (e *Engine) DiscoverControllers(ctx context.Context, base string) ([]*models.DomainController, error) {
	// Domain controllers carry serverReferenceBL and are computers; we query
	// them by objectCategory computer within the "Domain Controllers" OU.
	entries, err := e.Dir.Search(ctx, base,
		"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
		[]string{"cn", "name", "distinguishedName", "dNSHostName", "operatingSystem", "userAccountControl"})
	if err != nil {
		entries, err = e.Dir.Search(ctx, base, "(objectCategory=computer)",
			[]string{"cn", "name", "distinguishedName", "dNSHostName", "operatingSystem"})
		if err != nil {
			return nil, err
		}
	}

	var dcs []*models.DomainController
	for _, ent := range entries {
		dc := &models.DomainController{
			ID:              models.NewID("dc"),
			DistName:        ent.DN,
			Hostname:        first(ent.Value("dNSHostName"), ent.Value("name"), ent.Value("cn")),
			Domain:          domainFromBase(base),
			OperatingSystem: ent.Value("operatingSystem"),
			State:           models.StateObserved,
			DiscoveredAt:    now(),
		}
		dcs = append(dcs, dc)
		e.emitDC(dc)
	}
	return dcs, nil
}

// DiscoverRoot runs the full discovery pass: domains then controllers.
func (e *Engine) DiscoverRoot(ctx context.Context) (*Result, error) {
	res := &Result{}
	domains, base, err := e.DiscoverDomains(ctx)
	if err != nil {
		return res, err
	}
	res.Domains = domains
	res.BaseDN = base

	dcs, err := e.DiscoverControllers(ctx, base)
	if err == nil {
		res.DCS = dcs
	}
	return res, nil
}

func (e *Engine) emitDomain(d *models.Domain) {
	if e.Events == nil {
		return
	}
	e.Events.Info(events.DomainDiscovered, map[string]any{
		"domain": d.Name, "id": d.ID, "base_dn": d.BaseDN,
	})
}

func (e *Engine) emitDC(dc *models.DomainController) {
	if e.Events == nil {
		return
	}
	e.Events.Info(events.DomainControllerDiscov, map[string]any{
		"hostname": dc.Hostname, "id": dc.ID, "domain": dc.Domain,
	})
}

// Helpers --------------------------------------------------------------------

func domainFromBase(base string) string {
	var comps []string
	for _, part := range strings.Split(base, ",") {
		part = strings.TrimSpace(part)
		if len(part) >= 4 && strings.EqualFold(part[:3], "DC=") {
			comps = append(comps, part[3:])
		}
	}
	return strings.Join(comps, ".")
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func now() time.Time { return time.Now().UTC() }
