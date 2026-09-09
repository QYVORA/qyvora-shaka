// Package builtin registers shaka's built-in Active Directory assessment
// rules. Each rule is a deterministic detection over discovered directory
// objects; findings are backed by evidence and explicitly sorted.
package builtin

import (
	"sort"
	"strconv"
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
		kerberoastable(),
		weakAuthEncryption(),
		externalTrust(),
		trustRelationship(),
		constrainedDelegation(),
		computerUnconstrainedDelegation(),
		computerAllowsRBCT(),
		riskyServicePrincipalClass(),
		credentialInDescription(),
		sidHistoryPresent(),
		nestedPrivilegedMembership(),
		lapsNotApplied(),
		privilegedGPOLink(),
		weakPasswordPolicy(),
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
						"privilege", models.SeverityHigh, models.ConfidenceHigh)
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
						"authentication", models.SeverityMedium, models.ConfidenceHigh)
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
						"kerberos", models.SeverityHigh, models.ConfidenceHigh)
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
						"kerberos", models.SeverityHigh, models.ConfidenceMedium)
					f.Description = "Account " + u.SAMAccount + " is trusted for delegation."
					f.Objects = []string{u.SAMAccount}
					findings = append(findings, f)
				}
			}
			return findings
		},
	}
}

// ADM-007 flags accounts with registered service principal names (SPNs): they
// are kerberoastable targets once any domain credential is obtained.
func kerberoastable() *rules.Rule {
	return &rules.Rule{
		ID: "ADM-007", Name: "Kerberoastable Account (SPN Set)",
		Description: "An account has one or more service principal names and is therefore a kerberoastable target for offline password cracking.",
		Category:    "kerberos", Severity: models.SeverityMedium,
		Confidence:  models.ConfidenceHigh,
		ObjectTypes: []string{"user"},
		Remediation: "Rotate the account password, prefer group Managed Service Accounts (gMSA), and monitor TGS-REQ for SPNs.",
		Detect: func(ctx rules.Context) []*models.Finding {
			var findings []*models.Finding
			for _, u := range ctx.Users {
				if u == nil || len(u.ServicePrincipalNames) == 0 {
					continue
				}
				f := newFinding("ADM-007", "Kerberoastable Account (SPN Set)",
					"kerberos", models.SeverityMedium, models.ConfidenceHigh)
				f.Description = "Account " + u.SAMAccount + " has " +
					strconv.Itoa(len(u.ServicePrincipalNames)) + " service principal name(s) and is kerberoastable."
				f.Objects = []string{u.SAMAccount}
				f.Attributes = map[string]string{"sam": u.SAMAccount, "spn_count": strconv.Itoa(len(u.ServicePrincipalNames))}
				if u.AdminCount {
					f.Severity = models.SeverityHigh
					f.Impact = "A privileged account that is kerberoastable exposes a crackable high-value secret."
				}
				findings = append(findings, f)
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
						"authentication", models.SeverityMedium, models.ConfidenceMedium)
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
						"trust", models.SeverityMedium, models.ConfidenceMedium)
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
					"trust", models.SeverityInformational, models.ConfidenceMedium)
				f.Description = t.SourceDomain + " trusts " + t.TargetDomain + " (" + t.Type + ", " + t.Direction + ")."
				f.Objects = []string{t.SourceDomain, t.TargetDomain}
				findings = append(findings, f)
			}
			return findings
		},
	}
}

// ADM-008 flags accounts configured for constrained delegation (a fixed
// msDS-AllowedToDelegateTo target list). Constrained delegation is safer than
// unconstrained but is still an impersonation surface worth reviewing.
func constrainedDelegation() *rules.Rule {
	return &rules.Rule{
		ID: "ADM-008", Name: "Constrained Delegation Configured",
		Description: "An account carries a configured msDS-AllowedToDelegateTo list, authorizing it to impersonate users to specific services.",
		Category:    "kerberos", Severity: models.SeverityMedium,
		Confidence:  models.ConfidenceHigh,
		ObjectTypes: []string{"user", "computer"},
		Remediation: "Confirm the delegated services are still required, prefer resource-based constrained delegation, and monitor S4U2Self/S4U2Proxy use.",
		Detect: func(ctx rules.Context) []*models.Finding {
			var findings []*models.Finding
			principals := make([]*models.User, 0, len(ctx.Users))
			for _, u := range ctx.Users {
				if u != nil {
					principals = append(principals, u)
				}
			}
			sort.Slice(principals, func(i, j int) bool { return principals[i].SAMAccount < principals[j].SAMAccount })
			for _, u := range principals {
				if len(u.AllowedToDelegateTo) == 0 {
					continue
				}
				f := newFinding("ADM-008", "Constrained Delegation Configured",
					"kerberos", models.SeverityMedium, models.ConfidenceHigh)
				f.Description = "Account " + u.SAMAccount + " is configured for constrained delegation to " +
					strconv.Itoa(len(u.AllowedToDelegateTo)) + " service(s)."
				f.Objects = []string{u.SAMAccount}
				f.Attributes = map[string]string{"sam": u.SAMAccount, "targets": strings.Join(u.AllowedToDelegateTo, ", ")}
				if u.AdminCount {
					f.Severity = models.SeverityHigh
					f.Impact = "A privileged account with constrained delegation widens the impersonation exposure."
				}
				findings = append(findings, f)
			}
			return findings
		},
	}
}

// ADM-009 flags machine accounts with unconstrained delegation. On computers
// this is the classic MS14-068 / credential-capture posture and the highest
// delegation risk in the environment.
func computerUnconstrainedDelegation() *rules.Rule {
	return &rules.Rule{
		ID: "ADM-009", Name: "Computer Account Unconstrained Delegation",
		Description: "A computer account is trusted for delegation (TRUSTED_FOR_DELEGATION), allowing it to capture users' delegable Kerberos tickets.",
		Category:    "kerberos", Severity: models.SeverityHigh,
		Confidence:  models.ConfidenceHigh,
		ObjectTypes: []string{"computer"},
		Remediation: "Disable unconstrained delegation on the computer and use constrained or resource-based constrained delegation instead.",
		Detect: func(ctx rules.Context) []*models.Finding {
			var findings []*models.Finding
			comps := make([]*models.Computer, 0, len(ctx.Computers))
			for _, c := range ctx.Computers {
				if c != nil {
					comps = append(comps, c)
				}
			}
			sort.Slice(comps, func(i, j int) bool { return comps[i].Name < comps[j].Name })
			for _, c := range comps {
				if !c.TrustedForDelegation {
					continue
				}
				f := newFinding("ADM-009", "Computer Account Unconstrained Delegation",
					"kerberos", models.SeverityHigh, models.ConfidenceHigh)
				f.Description = "Computer " + c.Name + " is trusted for delegation without constraint."
				f.Objects = []string{c.Name}
				f.Attributes = map[string]string{"computer": c.Name}
				findings = append(findings, f)
			}
			return findings
		},
	}
}

// ADM-010 flags computer accounts that allow resource-based constrained
// delegation (msDS-AllowedToActOnBehalfOfOtherIdentity). RBCD is a modern
// delegation model but remains an impersonation surface; the account named in
// the attribute may act on the computer's behalf.
func computerAllowsRBCT() *rules.Rule {
	return &rules.Rule{
		ID: "ADM-010", Name: "Computer Allows Resource-Based Constrained Delegation",
		Description: "A computer account carries msDS-AllowedToActOnBehalfOfOtherIdentity, permitting another principal to impersonate users to this computer.",
		Category:    "kerberos", Severity: models.SeverityMedium,
		Confidence:  models.ConfidenceHigh,
		ObjectTypes: []string{"computer"},
		Remediation: "Verify the trusted principal is legitimate; monitor S4U2Self/S4U2Proxy requests toward the computer.",
		Detect: func(ctx rules.Context) []*models.Finding {
			var findings []*models.Finding
			comps := make([]*models.Computer, 0, len(ctx.Computers))
			for _, c := range ctx.Computers {
				if c != nil {
					comps = append(comps, c)
				}
			}
			sort.Slice(comps, func(i, j int) bool { return comps[i].Name < comps[j].Name })
			for _, c := range comps {
				if c.AllowedToActOnBehalfOf == "" {
					continue
				}
				f := newFinding("ADM-010", "Computer Allows Resource-Based Constrained Delegation",
					"kerberos", models.SeverityMedium, models.ConfidenceHigh)
				f.Description = "Computer " + c.Name + " allows resource-based constrained delegation."
				f.Objects = []string{c.Name}
				f.Attributes = map[string]string{"computer": c.Name, "trusted_principal": c.AllowedToActOnBehalfOf}
				findings = append(findings, f)
			}
			return findings
		},
	}
}

// riskyServiceClasses are SPN service classes that routinely underpin
// high-value targets (databases, web servers, messaging, file shares).
var riskyServiceClasses = map[string]bool{
	"mssqlsvc": true, "http": true, "https": true, "exchange": true, "cifs": true, "wsman": true,
}

// ADM-011 flags SPN registrations whose service class targets high-value
// infrastructure. These accounts extend the kerberoastable surface beyond
// ADM-007 by surfacing which SPNs point at privileged services.
func riskyServicePrincipalClass() *rules.Rule {
	return &rules.Rule{
		ID: "ADM-011", Name: "Risky Service Principal Name Class",
		Description: "A principal registers an SPN for a high-value service class (SQL, HTTP/S, messaging, file share), expanding the kerberoastable and impersonation surface.",
		Category:    "kerberos", Severity: models.SeverityMedium,
		Confidence:  models.ConfidenceMedium,
		ObjectTypes: []string{"user", "computer"},
		Remediation: "Rotate the account password, move to gMSA, and reduce the number of SPNs pointing at the principal.",
		Detect: func(ctx rules.Context) []*models.Finding {
			var findings []*models.Finding
			type named struct {
				name string
				spns []string
				priv bool
			}
			var rows []named
			for _, c := range ctx.Computers {
				if c != nil && len(c.ServicePrincipalNames) > 0 {
					rows = append(rows, named{name: c.Name, spns: c.ServicePrincipalNames})
				}
			}
			for _, u := range ctx.Users {
				if u != nil && len(u.ServicePrincipalNames) > 0 {
					rows = append(rows, named{name: u.SAMAccount, spns: u.ServicePrincipalNames, priv: u.AdminCount})
				}
			}
			sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
			for _, r := range rows {
				for _, spn := range r.spns {
					class := serviceClassOf(spn)
					if !riskyServiceClasses[class] {
						continue
					}
					f := newFinding("ADM-011", "Risky Service Principal Name Class",
						"kerberos", models.SeverityMedium, models.ConfidenceMedium)
					f.Description = "Principal " + r.name + " registers the risky SPN class \"" + class + "\" (" + spn + ")."
					f.Objects = []string{r.name}
					f.Attributes = map[string]string{"principal": r.name, "class": class, "spn": spn}
					if r.priv {
						f.Severity = models.SeverityHigh
						f.Impact = "A privileged principal with a high-value SPN is a prime kerberoast target."
					}
					findings = append(findings, f)
				}
			}
			return findings
		},
	}
}

func serviceClassOf(spn string) string {
	part := spn
	if i := strings.IndexByte(part, '/'); i >= 0 {
		part = part[:i]
	}
	return strings.ToLower(strings.TrimSpace(part))
}

// credentialPatterns are common cleartext-credential phrasings found in user
// description attributes. Matching any one warrants investigation; the rule
// never asserts the password itself is in use.
var credentialPatterns = []string{
	"password1", "password123", "passw0rd", "p@ssw0rd", "pwd=",
	"initial password", "default password", "temporary password", "temp password",
}

// ADM-012 flags accounts whose description attribute embeds what looks like
// credential material. It is a strong hygiene signal that credentials are
// being stored in a directory-visible attribute.
func credentialInDescription() *rules.Rule {
	return &rules.Rule{
		ID: "ADM-012", Name: "Credential Material in Description",
		Description: "An account's description attribute contains text resembling a password, storing credential material in a directory-visible field.",
		Category:    "secrets", Severity: models.SeverityMedium,
		Confidence:  models.ConfidenceHigh,
		ObjectTypes: []string{"user"},
		Remediation: "Remove password material from the description attribute, rotate the account password, and change the note-taking process.",
		Detect: func(ctx rules.Context) []*models.Finding {
			var findings []*models.Finding
			for _, u := range ctx.Users {
				if u == nil || u.Description == "" {
					continue
				}
				lower := strings.ToLower(u.Description)
				matched := ""
				for _, p := range credentialPatterns {
					if strings.Contains(lower, p) {
						matched = p
						break
					}
				}
				if matched == "" {
					continue
				}
				f := newFinding("ADM-012", "Credential Material in Description",
					"secrets", models.SeverityMedium, models.ConfidenceHigh)
				f.Description = "Description for " + u.SAMAccount + " contains text resembling a password (\"" + matched + "\")."
				f.Objects = []string{u.SAMAccount}
				f.Attributes = map[string]string{"sam": u.SAMAccount, "pattern": matched}
				if u.AdminCount {
					f.Severity = models.SeverityHigh
					f.Impact = "A privileged account storing credential material in its description is a high-value exposure."
				}
				findings = append(findings, f)
			}
			return findings
		},
	}
}

// ADM-013 flags accounts carrying SID history. SID history is a legacy
// migration mechanism that maps to historical privileges; without SID
// filtering it can cross forest trust boundaries.
func sidHistoryPresent() *rules.Rule {
	return &rules.Rule{
		ID: "ADM-013", Name: "Account Has SID History",
		Description: "An account carries SID history, carrying security context from a previous domain or forest and potentially crossing privilege boundaries.",
		Category:    "trust", Severity: models.SeverityMedium,
		Confidence:  models.ConfidenceHigh,
		ObjectTypes: []string{"user"},
		Remediation: "Review the SID history entries, remove obsolete SIDs, and confirm SID filtering is enabled on all external trusts.",
		Detect: func(ctx rules.Context) []*models.Finding {
			var findings []*models.Finding
			for _, u := range ctx.Users {
				if u == nil || len(u.SIDHistory) == 0 {
					continue
				}
				f := newFinding("ADM-013", "Account Has SID History",
					"trust", models.SeverityMedium, models.ConfidenceHigh)
				f.Description = "Account " + u.SAMAccount + " carries " +
					strconv.Itoa(len(u.SIDHistory)) + " SID history value(s)."
				f.Objects = []string{u.SAMAccount}
				f.Attributes = map[string]string{"sam": u.SAMAccount, "sid_count": strconv.Itoa(len(u.SIDHistory))}
				if u.AdminCount {
					f.Severity = models.SeverityHigh
					f.Impact = "A privileged account with SID history can bridge security boundaries across domains."
				}
				findings = append(findings, f)
			}
			return findings
		},
	}
}

// isPrivilegedGroupName matches well-known privilege-holding group names.
func isPrivilegedGroupName(name string) bool {
	switch strings.ToLower(name) {
	case "domain admins", "enterprise admins", "schema admins",
		"administrators", "account operators", "server operators",
		"print operators", "backup operators", "dnsadmins",
		"group policy creators owners", "cert publishers":
		return true
	}
	return false
}

// nestedPrivilegedMembership fires when a user reaches a privileged group
// through nested group membership (a group that is itself a member of a
// privileged group). It directly resolves membership from the enumerated group
// objects, so it reflects observed directory data, not assumptions.
func nestedPrivilegedMembership() *rules.Rule {
	return &rules.Rule{
		ID: "ADM-014", Name: "Privileged Group Membership via Nesting",
		Description: "A user reaches a privileged group through nested group membership, inheriting elevated rights without being a direct member.",
		Category:    "privilege", Severity: models.SeverityHigh,
		Confidence:  models.ConfidenceHigh,
		ObjectTypes: []string{"user", "group"},
		Remediation: "Flatten privileged memberships, apply tiered administration, and remove users who should not hold indirect elevated access.",
		Detect: func(ctx rules.Context) []*models.Finding {
			groupsByName := map[string]*models.Group{}
			var roots []string
			for _, g := range ctx.Groups {
				if g == nil {
					continue
				}
				groupsByName[g.DistName] = g
				if isPrivilegedGroupName(g.Name) || g.AdminCount {
					roots = append(roots, g.DistName)
				}
			}
			reachable := map[string]bool{}
			seen := map[string]bool{}
			queue := append([]string(nil), roots...)
			for len(queue) > 0 {
				dn := queue[0]
				queue = queue[1:]
				if seen[dn] {
					continue
				}
				seen[dn] = true
				g := groupsByName[dn]
				if g == nil {
					continue
				}
				for _, m := range g.Members {
					if seen[m] {
						continue
					}
					queue = append(queue, m)
					if _, isGroup := groupsByName[m]; !isGroup {
						reachable[m] = true
					}
				}
			}
			if len(reachable) == 0 {
				return nil
			}
			var findings []*models.Finding
			for _, u := range ctx.Users {
				if u == nil || u.AdminCount || !reachable[u.DistName] {
					continue
				}
				f := newFinding("ADM-014", "Privileged Group Membership via Nesting",
					"privilege", models.SeverityHigh, models.ConfidenceHigh)
				f.Description = "User " + u.SAMAccount + " reaches a privileged group through nested group membership."
				f.Objects = []string{u.SAMAccount}
				f.Attributes = map[string]string{"sam": u.SAMAccount}
				findings = append(findings, f)
			}
			return findings
		},
	}
}

// lapsNotApplied flags non-domain-controller computers that do not carry an
// ms-Mcs-AdmPwdExpirationTime attribute: their local administrator password
// is not being rotated by LAPS. Domain controllers are excluded because LAPS
// does not apply to them.
func lapsNotApplied() *rules.Rule {
	return &rules.Rule{
		ID: "AUTH-002", Name: "Local Administrator Password Not Managed (LAPS)",
		Description: "A computer does not carry an ms-Mcs-AdmPwdExpirationTime attribute, so its local administrator password is not rotated by the Local Administrator Password Solution.",
		Category:    "configuration", Severity: models.SeverityMedium,
		Confidence:  models.ConfidenceHigh,
		ObjectTypes: []string{"computer"},
		Remediation: "Deploy LAPS or a similar credential-rotation solution on all workstations and servers so the local administrator password is unique and rotated.",
		Detect: func(ctx rules.Context) []*models.Finding {
			var findings []*models.Finding
			comps := make([]*models.Computer, 0, len(ctx.Computers))
			for _, c := range ctx.Computers {
				if c != nil {
					comps = append(comps, c)
				}
			}
			sort.Slice(comps, func(i, j int) bool { return comps[i].Name < comps[j].Name })
			for _, c := range comps {
				if c.LAPSManaged || strings.Contains(c.DistName, ",OU=Domain Controllers,") {
					continue
				}
				f := newFinding("AUTH-002", "Local Administrator Password Not Managed (LAPS)",
					"configuration", models.SeverityMedium, models.ConfidenceHigh)
				f.Description = "Computer " + c.Name + " has no ms-Mcs-AdmPwdExpirationTime; the local administrator password is not LAPS-managed."
				f.Objects = []string{c.Name}
				f.Attributes = map[string]string{"computer": c.Name}
				findings = append(findings, f)
			}
			return findings
		},
	}
}

// privilegedGPOLink flags Group Policy objects linked to high-value
// containers (the domain controllers OU). Policy settings applied there can
// govern credential handling and domain-joins, so unexpected links warrant
// review.
func privilegedGPOLink() *rules.Rule {
	return &rules.Rule{
		ID: "AUTH-003", Name: "Group Policy Linked to Privileged Container",
		Description: "A Group Policy Object is linked to a privileged container (the Domain Controllers OU), so its settings apply to the highest-value systems.",
		Category:    "policy", Severity: models.SeverityMedium,
		Confidence:  models.ConfidenceHigh,
		ObjectTypes: []string{"ou", "gpo"},
		Remediation: "Review the linked policies, confirm their settings are intentional, and restrict who may edit them.",
		Detect: func(ctx rules.Context) []*models.Finding {
			var findings []*models.Finding
			ous := make([]*models.OrganizationalUnit, 0, len(ctx.OUs))
			for _, ou := range ctx.OUs {
				if ou != nil {
					ous = append(ous, ou)
				}
			}
			sort.Slice(ous, func(i, j int) bool { return ous[i].DistName < ous[j].DistName })
			for _, ou := range ous {
				if len(ou.LinkedGPOs) == 0 || !isPrivilegedContainer(ou.DistName, ou.Name) {
					continue
				}
				f := newFinding("AUTH-003", "Group Policy Linked to Privileged Container",
					"policy", models.SeverityMedium, models.ConfidenceHigh)
				f.Description = "Group Policy is linked to privileged container " + ou.DistName + " (" +
					strconv.Itoa(len(ou.LinkedGPOs)) + " link(s))."
				f.Objects = []string{ou.DistName}
				f.Attributes = map[string]string{"container": ou.DistName, "link_count": strconv.Itoa(len(ou.LinkedGPOs))}
				findings = append(findings, f)
			}
			return findings
		},
	}
}

// isPrivilegedContainer reports whether an OU is a high-value container: the
// Domain Controllers OU is the canonical case.
func isPrivilegedContainer(dn, name string) bool {
	return strings.Contains(dn, ",OU=Domain Controllers,") ||
		strings.EqualFold(name, "Domain Controllers")
}

// weakPasswordPolicy flags a domain whose observed password policy is weaker
// than modern guidance (minimum length below 14, complexity disabled).
func weakPasswordPolicy() *rules.Rule {
	return &rules.Rule{
		ID: "AUTH-004", Name: "Weak Domain Password Policy",
		Description: "The domain password policy is weaker than modern guidance: minimum length below 14 and/or complexity disabled, accelerating offline and brute-force attacks.",
		Category:    "authentication", Severity: models.SeverityMedium,
		Confidence:  models.ConfidenceHigh,
		ObjectTypes: []string{"domain"},
		Remediation: "Raise the minimum password length to 14+ and enable complexity, then require a forced rotation for affected accounts.",
		Detect: func(ctx rules.Context) []*models.Finding {
			var findings []*models.Finding
			domains := make([]*models.Domain, 0, len(ctx.Domains))
			for _, d := range ctx.Domains {
				if d != nil {
					domains = append(domains, d)
				}
			}
			sort.Slice(domains, func(i, j int) bool { return domains[i].Name < domains[j].Name })
			for _, d := range domains {
				pp := d.PasswordPolicy
				if !pp.Observed {
					continue
				}
				short := pp.MinLength < 14
				noComplex := !pp.Complexity
				if !short && !noComplex {
					continue
				}
				sev := models.SeverityMedium
				if short && pp.MinLength < 8 && noComplex {
					sev = models.SeverityHigh
				}
				f := newFinding("AUTH-004", "Weak Domain Password Policy",
					"authentication", sev, models.ConfidenceHigh)
				f.Description = "Domain " + d.Name + " has a weak password policy: minimum length " +
					strconv.Itoa(pp.MinLength) + ", complexity " + strings.ToLower(strconv.FormatBool(pp.Complexity)) + "."
				f.Objects = []string{d.Name}
				f.Attributes = map[string]string{
					"domain": d.Name, "min_length": strconv.Itoa(pp.MinLength),
					"complexity":   strconv.FormatBool(pp.Complexity),
					"max_age_days": strconv.Itoa(pp.MaxAgeDays),
				}
				findings = append(findings, f)
			}
			return findings
		},
	}
}

func newFinding(rule, title, category string, sev models.Severity, conf models.Confidence) *models.Finding {
	return &models.Finding{
		ID:         models.NewID("fnd"),
		RuleID:     rule,
		Title:      title,
		Category:   category,
		Severity:   sev,
		Confidence: conf,
		Status:     models.StatusDetected,
		State:      models.StateObserved,
		Timestamp:  time.Now().UTC(),
		Attributes: map[string]string{},
	}
}
