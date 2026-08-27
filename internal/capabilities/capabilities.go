// Package capabilities exposes shaka's capabilities as machine-readable tool
// metadata. Each major capability (domain.discover, directory.enumerate,
// etc.) is representable as a tool with input/output schema, risk, target
// type, authorization and confirmation metadata. The future AI orchestrator
// lives above the frameworks and consumes this metadata; shaka itself does
// not embed an LLM.
package capabilities

import (
	"sort"

	"github.com/QYVORA/qyvora-shaka/internal/safety"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// Tool describes one callable capability.
type Tool struct {
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	Description  string           `json:"description"`
	Framework    string           `json:"framework"`
	Category     string           `json:"category"`
	Output       []string         `json:"output_schema"`
	Risk         models.RiskLevel `json:"risk"`
	AuthRequired bool             `json:"authorization_required"`
	TargetType   string           `json:"target_type"`
	Confirm      bool             `json:"confirmation_required"`
	Reversible   bool             `json:"reversible"`
	Duration     string           `json:"expected_duration,omitempty"`
}

// Catalog is the full set of shaka capabilities.
func Catalog() []Tool {
	tools := []Tool{
		{
			ID: "shaka.domain.discover", Name: "Discover domains and domain controllers",
			Description: "Discover domains and domain controllers of the authorized target.",
			Framework:   "shaka", Category: "discovery", Output: []string{"Domain", "DomainController"},
			Risk: models.RiskS1, AuthRequired: true, TargetType: "domain", Reversible: true,
		},
		{
			ID: "shaka.directory.enumerate", Name: "Enumerate directory objects",
			Description: "Enumerate users, groups, computers, OUs and policies from the directory.",
			Framework:   "shaka", Category: "enumeration", Output: []string{"User", "Group", "Computer", "OrganizationalUnit", "GroupPolicy"},
			Risk: models.RiskS1, AuthRequired: true, TargetType: "domain", Reversible: true,
		},
		{
			ID: "shaka.users.enumerate", Name: "Enumerate users",
			Description: "Enumerate user objects and their authentication-relevant attributes.",
			Framework:   "shaka", Category: "enumeration", Output: []string{"User"},
			Risk: models.RiskS1, AuthRequired: true, TargetType: "domain", Reversible: true,
		},
		{
			ID: "shaka.groups.enumerate", Name: "Enumerate groups",
			Description: "Enumerate groups and expand nested membership.",
			Framework:   "shaka", Category: "enumeration", Output: []string{"Group"},
			Risk: models.RiskS1, AuthRequired: true, TargetType: "domain", Reversible: true,
		},
		{
			ID: "shaka.computers.enumerate", Name: "Enumerate computers",
			Description: "Enumerate computer objects and their properties.",
			Framework:   "shaka", Category: "enumeration", Output: []string{"Computer"},
			Risk: models.RiskS1, AuthRequired: true, TargetType: "domain", Reversible: true,
		},
		{
			ID: "shaka.trusts.analyze", Name: "Analyze domain trusts",
			Description: "Analyze domain trust relationships and their security significance.",
			Framework:   "shaka", Category: "analysis", Output: []string{"Trust"},
			Risk: models.RiskS1, AuthRequired: true, TargetType: "domain", Reversible: true,
		},
		{
			ID: "shaka.kerberos.assess", Name: "Assess Kerberos configuration",
			Description: "Assess Kerberos and authentication configuration from account attributes.",
			Framework:   "shaka", Category: "analysis", Output: []string{"KerberosResult"},
			Risk: models.RiskS1, AuthRequired: true, TargetType: "domain", Reversible: true,
		},
		{
			ID: "shaka.identity.analyze", Name: "Analyze identity and privilege",
			Description: "Correlate identity, privileges and administrative relationships.",
			Framework:   "shaka", Category: "analysis", Output: []string{"IdentityResult"},
			Risk: models.RiskS1, AuthRequired: true, TargetType: "domain", Reversible: true,
		},
		{
			ID: "shaka.graph.analyze", Name: "Analyze the relationship graph",
			Description: "Build and analyze the Active Directory relationship graph and attack paths.",
			Framework:   "shaka", Category: "analysis", Output: []string{"Node", "Edge", "AttackPath"},
			Risk: models.RiskS1, AuthRequired: true, TargetType: "domain", Reversible: true,
		},
		{
			ID: "shaka.findings.list", Name: "List findings",
			Description: "List current assessment findings.",
			Framework:   "shaka", Category: "reporting", Output: []string{"Finding"},
			Risk: models.RiskS1, AuthRequired: false, TargetType: "session", Reversible: true,
		},
		{
			ID: "shaka.report.generate", Name: "Generate a report",
			Description: "Generate an assessment report in a chosen format.",
			Framework:   "shaka", Category: "reporting", Output: []string{"Report"},
			Risk: models.RiskS1, AuthRequired: false, TargetType: "session", Reversible: true,
		},
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].ID < tools[j].ID })
	return tools
}

// CatalogSafety returns the safety metadata for each capability, derived from
// the shared safety package so the two stay in agreement.
func CatalogSafety() []safety.OperationMetadata {
	src := []safety.OperationMetadata{
		safety.OpDomainDiscovery, safety.OpDirectoryEnumerate,
		safety.OpTrustAnalyze, safety.OpKerberosAssess,
	}
	return src
}
