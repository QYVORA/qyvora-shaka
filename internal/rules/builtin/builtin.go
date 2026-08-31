// Package builtin registers shaka's built-in Active Directory assessment
// rules. Each rule is a deterministic detection over discovered directory
// objects; findings are backed by evidence and explicitly sorted.
package builtin

import (
	"strings"
	"time"

	"github.com/QYVORA/qyvora-shaka/internal/rules"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// Builtin returns shaka's built-in rule set.
func Builtin() []*rules.Rule {
	return []*rules.Rule{
		privilegedMembership(),
		passwordNeverExpires(),
		preAuthNotRequired(),
		unconstrainedDelegation(),
		weakAuthEncryption(),
		externalTrust(),
		trustRelationship(),
	}
}

// privilegedMembership flags members of privileged groups: a direct,
// high-confidence signal of elevated access that warrants review of who
// holds it.
func privilegedMembership() *rules.Rule {
	return &rules.Rule{
		ID: "ADM-001", Name: "Privileged Group Membership Discovered",
		Description: "A user is a member of a privileged Active Directory group. Privileged membership is a security-relevant relationship; the assessor must understand who holds wide-reaching rights.",
		Category:    "privilege", Severity: models.SeverityHigh,
		Confidence:  models.ConfidenceHigh,
		ObjectTypes: []string{"user", "group"},
		Remediation: "Review each membership, confirm it is required for the role, and remove or scope unelevated access where possible. Enable tiered administration.",
		References:  []string{"MS-DS users/groups docs"},
		Detect: func(ctx rules.Context) []*models.Finding {
			// Evaluate group memberships from the graph via users marked
			// adminCount; the deep identity analyzer adds explicit member
			// relationships.
			_ = ctx.Groups
			var findings []*models.Finding
			for _, u := range ctx.Users {
				if u != nil && u.AdminCount {
					f := newFinding("ADM-001", "Privileged Group Membership Discovered",
						models.SeverityHigh, models.ConfidenceHigh)
					f.Description = "User " + u.SAMAccount + " is marked as a privileged account (adminCount set)."
					f.Impact = "The account may hold elevated directory rights."
					f.Recommendation = "Confirm whether elevated rights are required."
					f.Objects = []string{u.SAMAccount}
					f.Attributes = map[string]string{"sam": u.SAMAccount, "admin_count": "true"}
					findings = append(findings, f)
				}
			}
			return findings
		},
	}
}

// ADM-002 flags accounts with a password that never expires.
func passwordNeverExpires() *rules.Rule {
	return &rules.Rule{
		ID: "ADM-002", Name: "Account Password Never Expires",
		Description: "An account is configured so its password never expires, weakening credential hygiene.",
		Category:    "authentication", Severity: models.SeverityMedium,
		Confidence:  models.ConfidenceHigh,
		ObjectTypes: []string{"user"},
		Remediation: "Enforce a password rotation policy and remove DONT_EXPIRE_PASSWORD on the account.",
		Detect: func(ctx rules.Context) []*models.Finding {
			var findings []*models.Finding
			for _, u := range ctx.Users {
				if u != nil && u.PasswordNeverExpires {
					f := newFinding("ADM-002", "Account Password Never Expires",
						models.SeverityMedium, models.ConfidenceHigh)
					f.Description = "Password for " + u.SAMAccount + " is configured to never expire."
					f.Objects = []string{u.SAMAccount}
					if u.AdminCount {
						f.Severity = models.SeverityHigh
						f.Impact = "Privileged account with a non-expiring password increases credential-theft exposure."
					}
					findings = append(findings, f)
				}
			}
			return findings
		},
	}
}

// ADM-003 flags accounts where pre-authentication is not required.
func preAuthNotRequired() *rules.Rule {
	return &rules.Rule{
		ID: "ADM-003", Name: "Kerberos Pre-Authentication Not Required",
		Description: "An account does not require Kerberos pre-authentication, exposing it to AS-REP roasting.",
		Category:    "kerberos", Severity: models.SeverityHigh,
		Confidence:  models.ConfidenceHigh,
		ObjectTypes: []string{"user"},
		Remediation: "Enable Kerberos pre-authentication on the account unless a technical dependency requires otherwise.",
		Detect: func(ctx rules.Context) []*models.Finding {
			var findings []*models.Finding
			for _, u := range ctx.Users {
				if u != nil && u.KerberosPreAuthNotRequired {
					f := newFinding("ADM-003", "Kerberos Pre-Authentication Not Required",
						models.SeverityHigh, models.ConfidenceHigh)
					f.Description = "Account " + u.SAMAccount + " has DONT_REQUIRE_PREAUTH set; the account is a candidate for AS-REP roasting."
					f.Impact = "An attacker with any domain credential can request a crackable AS-REP."
					f.Objects = []string{u.SAMAccount}
					findings = append(findings, f)
				}
			}
			return findings
		},
	}
}

// ADM-004 flags accounts trusted for delegation without constraint.
func unconstrainedDelegation() *rules.Rule {
	return &rules.Rule{
		ID: "ADM-004", Name: "Unconstrained Delegation",
		Description: "An account is trusted for delegation, allowing it to impersonate users to services.",
		Category:    "kerberos", Severity: models.SeverityHigh,
		Confidence:  models.ConfidenceMedium,
		ObjectTypes: []string{"user", "computer"},
		Remediation: "Replace unconstrained delegation with constrained or resource-based constrained delegation and monitor the account.",
		Detect: func(ctx rules.Context) []*models.Finding {
			var findings []*models.Finding
			for _, u := range ctx.Users {
				if u != nil && u.TrustedForDelegation {
					f := newFinding("ADM-004", "Unconstrained Delegation",
						models.SeverityHigh, models.ConfidenceMedium)
					f.Description = "Account " + u.SAMAccount + " is trusted for delegation."
					f.Objects = []string{u.SAMAccount}
					findings = append(findings, f)
				}
			}
			return findings
		},
	}
}

// ADM-005 flags accounts that use DES-only encryption or weak crypto.
func weakAuthEncryption() *rules.Rule {
	return &rules.Rule{
		ID: "ADM-005", Name: "Weak or Legacy Authentication Encryption",
		Description: "An account permits DES encryption or does not require a password, weakening authentication secrets.",
		Category:    "authentication", Severity: models.SeverityMedium,
		Confidence:  models.ConfidenceMedium,
		ObjectTypes: []string{"user"},
		Remediation: "Disable DES-only encryption and require a password on the account.",
		Detect: func(ctx rules.Context) []*models.Finding {
			var findings []*models.Finding
			for _, u := range ctx.Users {
				if u == nil {
					continue
				}
				if u.DESOnly || u.PasswordNotRequired {
					f := newFinding("ADM-005", "Weak or Legacy Authentication Encryption",
						models.SeverityMedium, models.ConfidenceMedium)
					flag := "DES-only"
					if u.PasswordNotRequired {
						flag = "password not required"
					}
					f.Description = "Account " + u.SAMAccount + " uses weak authentication config (" + flag + ")."
					f.Objects = []string{u.SAMAccount}
					findings = append(findings, f)
				}
			}
			return findings
		},
	}
}

// ADM-006 flags cross-forest or external trusts (fed by the trust analyzer).
func externalTrust() *rules.Rule {
	return &rules.Rule{
		ID: "ADM-006", Name: "External or Forest Trust Present",
		Description: "The environment trusts an external or forest domain, widening the attack surface across domain boundaries.",
		Category:    "trust", Severity: models.SeverityMedium,
		Confidence:  models.ConfidenceMedium,
		ObjectTypes: []string{"trust"},
		Remediation: "Review trust necessity, enable SID filtering for external trusts, and monitor cross-domain activity.",
		Detect: func(ctx rules.Context) []*models.Finding {
			var findings []*models.Finding
			for _, t := range ctx.Trusts {
				if t == nil {
					continue
				}
				if t.Type == "external" || t.Type == "forest" {
					f := newFinding("ADM-006", "External or Forest Trust Present",
						models.SeverityMedium, models.ConfidenceMedium)
					f.Description = t.SourceDomain + " trusts " + t.TargetDomain + " (" + t.Type + ", " + t.Direction + ")."
					f.Objects = []string{t.SourceDomain, t.TargetDomain}
					findings = append(findings, f)
				}
			}
			return findings
		},
	}
}

// AUTH-001 flags any discovered trust (informational context).
func trustRelationship() *rules.Rule {
	return &rules.Rule{
		ID: "AUTH-001", Name: "Domain Trust Relationship",
		Description: "A domain trust relationship was discovered.",
		Category:    "trust", Severity: models.SeverityInformational,
		Confidence:  models.ConfidenceMedium,
		ObjectTypes: []string{"trust"},
		Remediation: "Review whether each trust is necessary and subject to monitoring.",
		Detect: func(ctx rules.Context) []*models.Finding {
			var findings []*models.Finding
			for _, t := range ctx.Trusts {
				if t == nil {
					continue
				}
				f := newFinding("AUTH-001", "Domain Trust Relationship",
					models.SeverityInformational, models.ConfidenceMedium)
				f.Description = t.SourceDomain + " trusts " + t.TargetDomain + " (" + t.Type + ", " + t.Direction + ")."
				f.Objects = []string{t.SourceDomain, t.TargetDomain}
				findings = append(findings, f)
			}
			return findings
		},
	}
}

func newFinding(rule, title string, sev models.Severity, conf models.Confidence) *models.Finding {
	return &models.Finding{
		ID:         models.NewID("fnd"),
		RuleID:     rule,
		Title:      title,
		Category:   strings.ToLower(title[:min(len(title), 1)]),
		Severity:   sev,
		Confidence: conf,
		Status:     models.StatusDetected,
		State:      models.StateObserved,
		Timestamp:  time.Now().UTC(),
		Attributes: map[string]string{},
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
