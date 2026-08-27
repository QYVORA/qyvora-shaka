package analysis

import (
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// IdentityResult is the output of the identity/privilege correlation pass. It
// explains how principals relate to privileged groups and resources.
type IdentityResult struct {
	PrivilegedPrincipals []PrincipalContext `json:"privileged_principals"`
	AdminToResources     []AdminRelation    `json:"admin_to_resources"`
}

// PrincipalContext summarises one principal's relationship to privilege.
type PrincipalContext struct {
	Principal  string   `json:"principal"`
	Kind       string   `json:"kind"`
	GroupPath  []string `json:"group_path"`
	Privileges []string `json:"privileges"`
	Sensitive  bool     `json:"sensitive"`
}

// AdminRelation records that a principal has administrative access to a
// resource (computer or domain).
type AdminRelation struct {
	Principal string `json:"principal"`
	Resource  string `json:"resource"`
	Kind      string `json:"kind"`
	Source    string `json:"source"`
}

// IdentityAnalyzer correlates users/groups/computers with privileged
// relationships. It is deliberately conservative: an "admin" claim is only
// made when the graph or directory evidence indicates it, never assumed.
type IdentityAnalyzer struct{}

// PrivilegedGroupNames are the well-known privilege-holding groups.
var PrivilegedGroupNames = map[string]bool{
	"domain admins": true, "enterprise admins": true, "schema admins": true,
	"administrators": true, "account operators": true, "server operators": true,
	"print operators": true, "backup operators": true, "dnsadmins": true,
	"group policy creators owners": true, "cert publishers": true,
}

// Analyze builds the identity/privilege correlation result.
func (a *IdentityAnalyzer) Analyze(users []*models.User, groups []*models.Group, g *models.Session) IdentityResult {
	res := IdentityResult{}
	byGroup := map[string]*models.Group{}
	for _, g2 := range groups {
		if g2 != nil {
			byGroup[g2.SAMAccount] = g2
		}
	}
	for _, u := range users {
		if u == nil {
			continue
		}
		if u.AdminCount {
			res.PrivilegedPrincipals = append(res.PrivilegedPrincipals, PrincipalContext{
				Principal: u.SAMAccount, Kind: "user",
				GroupPath:  []string{"adminCount"},
				Privileges: []string{"elevated directory access"},
				Sensitive:  true,
			})
		}
	}
	// Admin-to-resource relations derived from the graph admin edges present
	// in the session's edge set.
	for _, e := range g.Edges {
		if e.Type == models.RelAdminOf {
			res.AdminToResources = append(res.AdminToResources, AdminRelation{
				Principal: e.From, Resource: e.To, Kind: "graph", Source: e.Source,
			})
		}
	}
	return res
}
