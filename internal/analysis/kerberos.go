package analysis

import "github.com/QYVORA/qyvora-shaka/pkg/models"

// KerberosResult summarizes the assessed authentication configuration.
// The system distinguishes observed / inferred / unknown and never reports an
// assumption as a fact.
type KerberosResult struct {
	Realm                string `json:"realm"`
	PreAuthNotRequired   int    `json:"preauth_not_required_count"`
	TrustedForDelegation int    `json:"trusted_for_delegation_count"`
	DESOnly              int    `json:"des_only_count"`
	Observed             bool   `json:"observed"`
}

// KerberosAssessor evaluates account configuration relevant to authentication
// security from the discovered directory objects.
type KerberosAssessor struct{}

// Assess examines users for authentication-relevant flags.
func (a *KerberosAssessor) Assess(domain string, users []*models.User) KerberosResult {
	res := KerberosResult{Realm: domain}
	if len(users) == 0 {
		return res
	}
	res.Observed = true
	for _, u := range users {
		if u == nil {
			continue
		}
		if u.KerberosPreAuthNotRequired {
			res.PreAuthNotRequired++
		}
		if u.TrustedForDelegation {
			res.TrustedForDelegation++
		}
		if u.DESOnly {
			res.DESOnly++
		}
	}
	return res
}
