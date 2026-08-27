// Package safety implements the architectural safety model of shaka.
//
// Every meaningful assessment operation carries metadata describing its risk,
// target type, authorization requirement, whether it changes state, and whether
// it is reversible. The safety system is architectural, not a disclaimer:
// higher-risk operations require explicit confirmation, safe/default profiles
// perform only read-only reconnaissance, and preflight checks run before work
// begins.
package safety

import "github.com/QYVORA/qyvora-shaka/pkg/models"

// Class identifies a family of assessment operation.
type Class string

const (
	ClassDiscovery Class = "discovery"
	ClassEnumerat  Class = "enumeration"
	ClassAuthProbe Class = "authentication_probe"
	ClassAnalysis  Class = "analysis"
	ClassOffensive Class = "offensive"
)

// OperationMetadata describes one assessment operation's safety contract.
type OperationMetadata struct {
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	Description  string           `json:"description"`
	Class        Class            `json:"class"`
	Risk         models.RiskLevel `json:"risk"`
	TargetType   string           `json:"target_type"`
	AuthRequired bool             `json:"authorization_required"`
	Privileges   []string         `json:"privileges,omitempty"`
	Confirm      bool             `json:"confirmation_required"`
	ChangesState bool             `json:"changes_state"`
	Reversible   bool             `json:"reversible"`
}

// Known operations. Shaka's initial release is discovery/enumeration/analysis
// focused: all operations here are read-only (reversible, no state change),
// so the default safe posture is satisfied without sacrificing capability.
var (
	OpDomainDiscovery = OperationMetadata{
		ID: "shaka.domain.discover", Name: "domain discovery",
		Description: "Discover domains, domain controllers and the directory base.",
		Class:       ClassDiscovery, Risk: models.RiskS1, TargetType: "domain",
		AuthRequired: true, Privileges: []string{"read directory"},
		Confirm: false, ChangesState: false, Reversible: true,
	}
	OpDirectoryEnumerate = OperationMetadata{
		ID: "shaka.directory.enumerate", Name: "directory enumeration",
		Description: "Enumerate users, groups, computers, OUs and policies from LDAP.",
		Class:       ClassEnumerat, Risk: models.RiskS1, TargetType: "domain",
		AuthRequired: true, Privileges: []string{"read directory"},
		Confirm: false, ChangesState: false, Reversible: true,
	}
	OpTrustAnalyze = OperationMetadata{
		ID: "shaka.trusts.analyze", Name: "trust analysis",
		Description: "Enumerate and analyze domain trust relationships.",
		Class:       ClassEnumerat, Risk: models.RiskS1, TargetType: "domain",
		AuthRequired: true, Privileges: []string{"read directory"},
		Confirm: false, ChangesState: false, Reversible: true,
	}
	OpKerberosAssess = OperationMetadata{
		ID: "shaka.kerberos.assess", Name: "kerberos assessment",
		Description: "Assess Kerberos and authentication configuration.",
		Class:       ClassEnumerat, Risk: models.RiskS1, TargetType: "domain",
		AuthRequired: true, Privileges: []string{"read account configuration"},
		Confirm: false, ChangesState: false, Reversible: true,
	}
	OpAuthProbe = OperationMetadata{
		ID: "shaka.authentication.probe", Name: "authentication probe",
		Description: "Attempt an authentication probe (e.g. AS-REP / pre-auth).",
		Class:       ClassAuthProbe, Risk: models.RiskS2, TargetType: "domain",
		AuthRequired: true, Privileges: []string{"authentication"},
		Confirm: true, ChangesState: false, Reversible: true,
	}
)

// IsAllowed reports whether an operation may run under the given profile and
// escalation flags. Deep/research profiles allow read-only S1 operations
// freely; offensive S3/S4 work is never part of the initial release.
func IsAllowed(op OperationMetadata, profile string, confirmed bool, safeOnly bool) bool {
	if op.Risk.RequiresConfirmation() {
		if safeOnly && op.Risk.Rank() >= models.RiskS3.Rank() {
			return false
		}
		if op.Confirm && !confirmed {
			return false
		}
	}
	return op.ChangesState == false || op.Reversible
}
