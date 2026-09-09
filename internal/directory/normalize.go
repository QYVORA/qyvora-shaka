package directory

import (
	"strconv"
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
	// msDS-AllowedToDelegateTo is constrained delegation, a distinct
	// configuration from unconstrained delegation (TRUSTED_FOR_DELEGATION);
	// it must not set the unconstrained flag. It is captured separately below.
	if vals := attrVals(e, "msds-allowedtodelegateto"); len(vals) > 0 {
		u.AllowedToDelegateTo = dedupeStrings(append([]string(nil), vals...))
	}
	if has(e, "servicePrincipalName") || len(attrVals(e, "servicePrincipalName")) > 0 {
		u.ServicePrincipalNames = append([]string(nil), attrVals(e, "servicePrincipalName")...)
		u.ServicePrincipalNames = dedupeStrings(u.ServicePrincipalNames)
	}
	if vals := attrVals(e, "sidhistory"); len(vals) > 0 {
		u.SIDHistory = dedupeStrings(append([]string(nil), vals...))
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
	for _, v := range attrVals(e, "useraccountcontrol") {
		c.Enabled = boolPtr(!isAccountDisabled(v))
		break
	}
	if vals := attrVals(e, "useraccountcontrol"); len(vals) > 0 {
		if n, ok := uacInt(vals[0]); ok && n&0x80000 != 0 { // UF_TRUSTED_FOR_DELEGATION
			c.TrustedForDelegation = true
		}
	}
	if vals := attrVals(e, "msds-allowedtoactonbehalfofotheridentity"); len(vals) > 0 {
		c.AllowedToActOnBehalfOf = vals[0]
	}
	// Presence of ms-Mcs-AdmPwdExpirationTime indicates the LAPS agent is
	// managing the local administrator password.
	if vals := attrVals(e, "ms-mcs-admpwdexpirationtime"); len(vals) > 0 && vals[0] != "" {
		c.LAPSManaged = true
	}
	if vals := attrVals(e, "serviceprincipalname"); len(vals) > 0 {
		c.ServicePrincipalNames = dedupeStrings(append([]string(nil), vals...))
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
	ou := &models.OrganizationalUnit{
		ID:           models.NewID("ou"),
		DistName:     e.DN,
		Name:         firstNonEmpty(e.Value("name"), e.Value("ou"), e.Value("cn")),
		Domain:       domainOf(e.DN),
		State:        models.StateObserved,
		DiscoveredAt: time.Now().UTC(),
	}
	// gPLink is a list of LDAP://<GPO DN>;options pairs, e.g.
	// "[LDAP://CN={GUID},CN=Policies,CN=System,DC=...;0][LDAP://CN={GUID2},...;1]".
	ou.LinkedGPOs = parseGPLinks(e.Value("gPLink"))
	return ou
}

// parseGPLinks extracts the GPO distinguished names from an Active Directory
// gPLink value, stripping the LDAP:// transport prefix and the link options
// (";0", ";1"). Values that are not structurally sound are skipped.
func parseGPLinks(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, "][") {
		part = strings.Trim(part, "[] ")
		if !strings.HasPrefix(part, "LDAP://") {
			continue
		}
		dn := strings.TrimPrefix(part, "LDAP://")
		if i := strings.IndexByte(dn, ';'); i >= 0 {
			dn = dn[:i]
		}
		if dn == "" || !strings.Contains(dn, "=") {
			continue
		}
		out = append(out, dn)
	}
	return dedupeStrings(out)
}

// ApplyDomainPasswordPolicy reads the domain password policy attributes from a
// domain object entry into the model. The policy is only marked observed when
// the underlying attributes were actually present; otherwise the model stays
// "unknown" and rules must not fire.
func ApplyDomainPasswordPolicy(d *models.Domain, e *transport.Entry) {
	applyPasswordPolicy(d, e)
}

// applyPasswordPolicy implements the policy mapping for ApplyDomainPasswordPolicy.
func applyPasswordPolicy(d *models.Domain, e *transport.Entry) {
	if d == nil || e == nil {
		return
	}
	vals := attrVals(e, "minpwdlen")
	if len(vals) == 0 || vals[0] == "" {
		return
	}
	pp := models.PasswordPolicy{Observed: true}
	if n, ok := parseIntSafe(vals[0]); ok {
		pp.MinLength = n
	}
	if props, ok := parseIntSafe(e.Value("pwdProperties")); ok {
		pp.Complexity = props&0x1 != 0 // DOMAIN_PASSWORD_COMPLEX
	}
	if age, ok := parseInt64Safe(e.Value("maxPwdAge")); ok {
		if age < 0 {
			age = -age
		}
		pp.MaxAgeDays = int(age / 864000000000) // 100ns units → days
	}
	d.PasswordPolicy = pp
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

// NormalizeTrust converts a trustedDomain directory entry into a Trust model,
// decoding the LDAP integer attributes into the semantic fields used by the
// trust analyzer and rules. Mapping mirrors the standard Active Directory
// trust enumeration (BloodHound/ADACL style):
//
//   - trustDirection: 1=outbound, 2=inbound, 3=bidirectional
//   - trustType:      2=external(down-level), 3=parent_child (Kerberos),
//     4=forest, anything else treated as external
//   - trustAttributes bit flags: 0x1 = NON_TRANSITIVE, 0x200 = QUARANTINED
//     (SID filtering enabled), 0x10 = SID_HISTORY (filtering disabled)
func NormalizeTrust(e *transport.Entry) *models.Trust {
	dir := trustDirection(e.Value("trustDirection"))
	typ := trustType(e.Value("trustType"))
	attrs := trustAttributes(e.Value("trustAttributes"))
	return &models.Trust{
		ID:            models.NewID("trust"),
		SourceDomain:  domainOf(e.DN),
		TargetDomain:  firstNonEmpty(e.Value("cn"), e.Value("name")),
		Direction:     dir,
		Type:          typ,
		Transitive:    attrs&attrNonTransitive == 0,
		IsSIDFiltered: attrs&attrQuarantined != 0,
		State:         models.StateObserved,
		Confidence:    models.ConfidenceHigh,
		DiscoveredAt:  time.Now().UTC(),
	}
}

// Trust attribute bit flags.
const (
	attrNonTransitive uint32 = 0x1
	attrSIDHistory    uint32 = 0x10
	attrQuarantined   uint32 = 0x200
)

func trustDirection(v string) string {
	switch v {
	case "1":
		return "outbound"
	case "2":
		return "inbound"
	case "3":
		return "bidirectional"
	}
	return "unknown"
}

func trustType(v string) string {
	switch v {
	case "3":
		return "parent_child"
	case "4":
		return "forest"
	}
	return "external"
}

func trustAttributes(v string) uint32 {
	var n uint32
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + uint32(c-'0')
	}
	return n
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

func parseIntSafe(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	return n, err == nil
}

func parseInt64Safe(s string) (int64, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n, err == nil
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
