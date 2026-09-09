package models

import "time"

// DirectoryObjectType identifies the LDAP object class of a discovered object.
type DirectoryObjectType string

const (
	ObjectDomain   DirectoryObjectType = "domain"
	ObjectDC       DirectoryObjectType = "domain_controller"
	ObjectComputer DirectoryObjectType = "computer"
	ObjectUser     DirectoryObjectType = "user"
	ObjectGroup    DirectoryObjectType = "group"
	ObjectOU       DirectoryObjectType = "ou"
	ObjectGPO      DirectoryObjectType = "gpo"
	ObjectService  DirectoryObjectType = "service"
)

// Domain describes an Active Directory domain.
type Domain struct {
	ID              string         `json:"id"`
	DistName        string         `json:"distinguished_name,omitempty"`
	Name            string         `json:"name"`
	NetBIOS         string         `json:"netbios_name,omitempty"`
	SID             string         `json:"sid,omitempty"`
	BaseDN          string         `json:"base_dn,omitempty"`
	FunctionalLevel int            `json:"functional_level,omitempty"`
	PasswordPolicy  PasswordPolicy `json:"password_policy,omitempty"`
	State           State          `json:"state"`
	DiscoveredAt    time.Time      `json:"discovered_at"`
}

// PasswordPolicy captures the domain password policy observed on the domain
// object. MinLength and Complexity are only meaningful when Observed is true;
// the framework never assumes policy values that were not read from the
// directory.
type PasswordPolicy struct {
	Observed   bool `json:"observed,omitempty"`
	MinLength  int  `json:"min_length,omitempty"`
	Complexity bool `json:"complexity_enabled,omitempty"`
	MaxAgeDays int  `json:"max_age_days,omitempty"`
}

// DomainController describes a directory server for a domain.
type DomainController struct {
	ID              string    `json:"id"`
	DistName        string    `json:"distinguished_name,omitempty"`
	Hostname        string    `json:"hostname"`
	Domain          string    `json:"domain,omitempty"`
	Address         string    `json:"address,omitempty"`
	OperatingSystem string    `json:"operating_system,omitempty"`
	IsGC            bool      `json:"is_global_catalog,omitempty"`
	IsRODC          bool      `json:"is_rodc,omitempty"`
	State           State     `json:"state"`
	DiscoveredAt    time.Time `json:"discovered_at"`
}

// Computer describes a joined computer object.
type Computer struct {
	ID              string    `json:"id"`
	DistName        string    `json:"distinguished_name,omitempty"`
	Name            string    `json:"name"`
	Domain          string    `json:"domain,omitempty"`
	OperatingSystem string    `json:"operating_system,omitempty"`
	OSVersion       string    `json:"os_version,omitempty"`
	DNSName         string    `json:"dns_name,omitempty"`
	IPv4            string    `json:"ipv4,omitempty"`
	Enabled         *bool     `json:"enabled,omitempty"`
	LastLogon       time.Time `json:"last_logon,omitempty"`
	// TrustedForDelegation is set when the computer account carries the
	// TRUSTED_FOR_DELEGATION userAccountControl bit (unconstrained
	// delegation), a dangerous delegation posture for machine accounts.
	TrustedForDelegation bool `json:"trusted_for_delegation,omitempty"`
	// AllowedToActOnBehalfOf is present when the computer has
	// msDS-AllowedToActOnBehalfOfOtherIdentity (resource-based constrained
	// delegation), allowing another principal to impersonate users to it.
	AllowedToActOnBehalfOf string `json:"allowed_to_act_on_behalf_of,omitempty"`
	// LAPSManaged is true when the computer has an ms-Mcs-AdmPwdExpirationTime
	// attribute, indicating the Local Administrator Password Solution is
	// managing its local admin account.
	LAPSManaged bool `json:"laps_managed,omitempty"`
	// ServicePrincipalNames holds the computer account's registered SPNs.
	ServicePrincipalNames []string  `json:"spns,omitempty"`
	State                 State     `json:"state"`
	DiscoveredAt          time.Time `json:"discovered_at"`
}

// User describes an identity object.
type User struct {
	ID          string `json:"id"`
	DistName    string `json:"distinguished_name,omitempty"`
	Name        string `json:"name"`
	SAMAccount  string `json:"sam_account_name"`
	UPN         string `json:"user_principal_name,omitempty"`
	Domain      string `json:"domain,omitempty"`
	Enabled     *bool  `json:"enabled,omitempty"`
	AdminCount  bool   `json:"admin_count,omitempty"`
	Description string `json:"description,omitempty"`
	// Security flags relevant to authentication configuration.
	PasswordNeverExpires       bool     `json:"password_never_expires,omitempty"`
	PasswordNotRequired        bool     `json:"password_not_required,omitempty"`
	KerberosPreAuthNotRequired bool     `json:"kerberos_preauth_not_required,omitempty"`
	DoNotRequirePreAuth        bool     `json:"do_not_require_preauth,omitempty"`
	DESOnly                    bool     `json:"des_only,omitempty"`
	SmartcardRequired          bool     `json:"smartcard_required,omitempty"`
	TrustedForDelegation       bool     `json:"trusted_for_delegation,omitempty"`
	ServicePrincipalNames      []string `json:"spns,omitempty"`
	// AllowedToDelegateTo holds the msDS-AllowedToDelegateTo values: the
	// services another configured principal may access while impersonating a
	// user (constrained delegation target list).
	AllowedToDelegateTo []string `json:"allowed_to_delegate_to,omitempty"`
	// SIDHistory holds the security identifier history attribute; SID history
	// grants the historical security context of a migrated account and can
	// cross privilege boundaries when SID filtering is absent.
	SIDHistory   []string  `json:"sid_history,omitempty"`
	LastLogon    time.Time `json:"last_logon,omitempty"`
	State        State     `json:"state"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// Group describes a security or distribution group.
type Group struct {
	ID          string `json:"id"`
	DistName    string `json:"distinguished_name,omitempty"`
	Name        string `json:"name"`
	SAMAccount  string `json:"sam_account_name"`
	Domain      string `json:"domain,omitempty"`
	IsSecurity  bool   `json:"is_security,omitempty"`
	AdminCount  bool   `json:"admin_count,omitempty"`
	Description string `json:"description,omitempty"`
	// Members holds the distinguished names of direct members (used to build
	// membership relationships in the graph).
	Members      []string  `json:"members,omitempty"`
	State        State     `json:"state"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// OrganizationalUnit describes an organizational unit.
type OrganizationalUnit struct {
	ID       string `json:"id"`
	DistName string `json:"distinguished_name"`
	Name     string `json:"name"`
	Domain   string `json:"domain,omitempty"`
	// LinkedGPOs holds the GPO distinguished names extracted from the OU's
	// gPLink attribute (the Group Policy links scoped to this container).
	LinkedGPOs   []string  `json:"linked_gpos,omitempty"`
	State        State     `json:"state"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// GroupPolicy describes a Group Policy Object.
type GroupPolicy struct {
	ID           string    `json:"id"`
	DistName     string    `json:"distinguished_name"`
	Name         string    `json:"name"`
	Domain       string    `json:"domain,omitempty"`
	State        State     `json:"state"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// Service describes a discovered service on a computer.
type Service struct {
	ID           string    `json:"id"`
	Computer     string    `json:"computer,omitempty"`
	Name         string    `json:"name"`
	Port         int       `json:"port,omitempty"`
	Proto        string    `json:"protocol,omitempty"`
	Banner       string    `json:"banner,omitempty"`
	State        State     `json:"state"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// Trust describes a trust relationship between two domains.
type Trust struct {
	ID            string     `json:"id"`
	SourceDomain  string     `json:"source_domain"`
	TargetDomain  string     `json:"target_domain"`
	Direction     string     `json:"direction"` // inbound|outbound|bidirectional
	Type          string     `json:"type"`      // external|forest|parent_child|shortcut
	Transitive    bool       `json:"transitive,omitempty"`
	IsSIDFiltered bool       `json:"is_sid_filtered,omitempty"`
	State         State      `json:"state"`
	Confidence    Confidence `json:"confidence,omitempty"`
	EvidenceIDs   []string   `json:"evidence_ids,omitempty"`
	DiscoveredAt  time.Time  `json:"discovered_at"`
}
