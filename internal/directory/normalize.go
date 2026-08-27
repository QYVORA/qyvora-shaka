package directory

import (
	"strings"
	"time"

	"github.com/QYVORA/qyvora-shaka/internal/transport"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// NormalizeUser converts a directory entry into a User model, normalizing
// common Active Directory attribute spellings and account-control flags.
func NormalizeUser(e *transport.Entry) *models.User {
	u := &models.User{
		ID:           models.NewID("user"),
		DistName:     e.DN,
		SAMAccount:   e.Value("sAMAccountName"),
		UPN:          e.Value("userPrincipalName"),
		Name:         firstNonEmpty(e.Value("name"), e.Value("cn"), e.Value("sAMAccountName")),
		Domain:       domainOf(e.DN),
		Description:  e.Value("description"),
		State:        models.StateObserved,
		DiscoveredAt: time.Now().UTC(),
	}
	if v := e.Value("adminCount"); v == "1" || v == "true" {
		u.AdminCount = true
	}
	if v := e.Value("userAccountControl"); v != "" {
		applyUAC(&u.PasswordNeverExpires, &u.PasswordNotRequired,
			&u.KerberosPreAuthNotRequired, &u.DoNotRequirePreAuth,
			&u.DESOnly, &u.SmartcardRequired, &u.TrustedForDelegation, v)
	}
	// Common aliases for delegation / preauth flags.
	if has(e, "msDS-AllowedToDelegateTo") || u.TrustedForDelegation {
		u.TrustedForDelegation = true
	}
	if has(e, "servicePrincipalName") || len(attrVals(e, "servicePrincipalName")) > 0 {
		u.ServicePrincipalNames = append([]string(nil), attrVals(e, "servicePrincipalName")...)
		u.ServicePrincipalNames = dedupeStrings(u.ServicePrincipalNames)
	}
	u.Enabled = nil
	for _, v := range attrVals(e, "useraccountcontrol") {
		u.Enabled = boolPtr(!isAccountDisabled(v))
		break
	}
	if le := e.Value("lastLogonTimestamp"); le != "" {
		if t, err := parseWindowsFiletime(le); err == nil {
			u.LastLogon = t
		}
	}
	return u
}

// NormalizeGroup converts a directory entry into a Group model.
func NormalizeGroup(e *transport.Entry) *models.Group {
	g := &models.Group{
		ID:           models.NewID("group"),
		DistName:     e.DN,
		SAMAccount:   e.Value("sAMAccountName"),
		Name:         firstNonEmpty(e.Value("name"), e.Value("cn"), e.Value("sAMAccountName")),
		Domain:       domainOf(e.DN),
		Description:  e.Value("description"),
		State:        models.StateObserved,
		DiscoveredAt: time.Now().UTC(),
	}
	if v := e.Value("adminCount"); v == "1" || v == "true" {
		g.AdminCount = true
	}
	g.IsSecurity = has(e, "groupType")
	g.Members = append([]string{}, attrVals(e, "member")...)
	return g
}

// NormalizeComputer converts a directory entry into a Computer model.
func NormalizeComputer(e *transport.Entry) *models.Computer {
	c := &models.Computer{
		ID:              models.NewID("computer"),
		DistName:        e.DN,
		Name:            firstNonEmpty(e.Value("name"), e.Value("cn")),
		Domain:          domainOf(e.DN),
		OperatingSystem: e.Value("operatingSystem"),
		OSVersion:       e.Value("operatingSystemVersion"),
		DNSName:         e.Value("dNSHostName"),
		IPv4:            e.Value("ipv4Address"),
		State:           models.StateObserved,
		DiscoveredAt:    time.Now().UTC(),
	}
	for _, v := range e.Attributes["useraccountcontrol"] {
		c.Enabled = boolPtr(!isAccountDisabled(v))
		break
	}
	if le := e.Value("lastLogonTimestamp"); le != "" {
		if t, err := parseWindowsFiletime(le); err == nil {
			c.LastLogon = t
		}
	}
	return c
}

// NormalizeOU converts a directory entry into an OU model.
func NormalizeOU(e *transport.Entry) *models.OrganizationalUnit {
	return &models.OrganizationalUnit{
		ID:           models.NewID("ou"),
		DistName:     e.DN,
		Name:         firstNonEmpty(e.Value("name"), e.Value("ou"), e.Value("cn")),
		Domain:       domainOf(e.DN),
		State:        models.StateObserved,
		DiscoveredAt: time.Now().UTC(),
	}
}

// NormalizeGPO converts a directory entry into a GPO model.
func NormalizeGPO(e *transport.Entry) *models.GroupPolicy {
	return &models.GroupPolicy{
		ID:           models.NewID("gpo"),
		DistName:     e.DN,
		Name:         firstNonEmpty(e.Value("name"), e.Value("cn")),
		Domain:       domainOf(e.DN),
		State:        models.StateObserved,
		DiscoveredAt: time.Now().UTC(),
	}
}

// Helper accessors -----------------------------------------------------------

func has(e *transport.Entry, attr string) bool {
	return len(attrVals(e, attr)) > 0
}

// attrVals returns the values for an attribute using a case-insensitive key
// lookup (LDAP attribute names are case-insensitive).
func attrVals(e *transport.Entry, attr string) []string {
	for k, v := range e.Attributes {
		if strings.EqualFold(k, attr) {
			return v
		}
	}
	return nil
}

func domainOf(dn string) string {
	// Extract the first DC component, e.g. DC=corp,DC=com -> corp.com.
	var comps []string
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "DC=") {
			comps = append(comps, strings.TrimPrefix(part[3:], " "))
		}
	}
	return strings.Join(comps, ".")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func boolPtr(b bool) *bool { return &b }

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// isAccountDisabled inspects the userAccountControl integer flag.
func isAccountDisabled(uac string) bool {
	v, ok := uacInt(uac)
	if !ok {
		return false
	}
	return v&0x0002 != 0 // UF_ACCOUNTDISABLE
}

func uacInt(uac string) (uint32, bool) {
	var v uint32
	for _, c := range uac {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + uint32(c-'0')
	}
	return v, true
}

// applyUAC decodes userAccountControl flags into the user model booleans.
func applyUAC(neverExpires, notRequired, preAuthNotReq, doNotReqPreauth, desOnly, smartcard, trustedForDelegation *bool, uac string) {
	v, ok := uacInt(uac)
	if !ok {
		return
	}
	if v&0x10000 != 0 { // UF_DONT_EXPIRE_PASSWD
		*neverExpires = true
	}
	if v&0x20 != 0 { // UF_PASSWD_NOTREQD
		*notRequired = true
	}
	if v&0x400000 != 0 { // UF_DONT_REQUIRE_PREAUTH
		*preAuthNotReq = true
		*doNotReqPreauth = true
	}
	if v&0x200000 != 0 { // UF_USE_DES_KEY_ONLY
		*desOnly = true
	}
	if v&0x40000 != 0 { // UF_SMARTCARD_REQUIRED
		*smartcard = true
	}
	if v&0x80000 != 0 { // UF_TRUSTED_FOR_DELEGATION
		*trustedForDelegation = true
	}
}

// parseWindowsFiletime converts a Windows FILETIME (100ns since 1601) in
// decimal string form to a time.Time.
func parseWindowsFiletime(s string) (time.Time, error) {
	var ft uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return time.Time{}, errNotFiletime
		}
		ft = ft*10 + uint64(c-'0')
	}
	const unixEpoch = 116444736000000000
	if ft < unixEpoch {
		return time.Time{}, errNotFiletime
	}
	ns := int64((ft - unixEpoch) * 100)
	return time.Unix(0, ns).UTC(), nil
}

var errNotFiletime = &filetimeErr{}

type filetimeErr struct{}

func (e *filetimeErr) Error() string { return "not a windows filetime" }
