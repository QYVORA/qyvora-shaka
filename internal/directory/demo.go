package directory

import (
	"fmt"

	"github.com/QYVORA/qyvora-shaka/internal/transport"
)

// Demo builds a small but realistic in-memory Active Directory fixture. It
// exercises the discovery/enumeration/graph/rules path for offline demo and
// deterministic tests. Attributes mirror what the enumerators request.
func Demo() *Simulator {
	const base = "DC=corp,DC=example,DC=com"
	sim := NewSimulator(base)

	// Root DSE entry used to derive the base DN.
	sim.Add(&transport.Entry{DN: "", Attributes: map[string][]string{
		"defaultNamingContext": {base},
	}})

	// The domain object itself, carrying the observed password policy.
	sim.Add(&transport.Entry{DN: base, Attributes: map[string][]string{
		"objectClass": {"domain"}, "name": {"corp"}, "distinguishedName": {base},
		// Weak policy: minimum length 8, complexity on, 42-day max age.
		"minPwdLen": {"8"}, "pwdProperties": {"1"}, "maxPwdAge": {"-36288000000000"},
	}})

	// A domain controller (computer object + its DC presence).
	sim.Add(&transport.Entry{DN: "CN=DC01,OU=Domain Controllers," + base, Attributes: map[string][]string{
		"objectClass": {"computer", "user"}, "objectCategory": {"computer"},
		"cn": {"DC01"}, "name": {"DC01"}, "sAMAccountName": {"DC01$"},
		"distinguishedName":  {"CN=DC01,OU=Domain Controllers," + base},
		"operatingSystem":    {"Windows Server 2022"},
		"dNSHostName":        {"dc01.corp.example.com"},
		"userAccountControl": {"532480"}, // TRUSTED_FOR_DELEGATION | WORKSTATION
	}})

	addUser(sim, base, "Administrator", "Administrator", "Administrator@corp.example.com", true)
	addUser(sim, base, "svc-backup", "svc-backup", "svc-backup@corp.example.com", false)
	addUser(sim, base, "jdoe", "John Doe", "jdoe@corp.example.com", false)
	addUser(sim, base, "kpreauth", "Kari PreAuth", "kpreauth@corp.example.com", false)
	// Constrained delegation (ADM-008): SPN + msDS-AllowedToDelegateTo.
	addUser(sim, base, "svc-web", "svc-web", "svc-web@corp.example.com", false, map[string][]string{
		"servicePrincipalName":     {"HTTP/web.corp.example.com"},
		"msDS-AllowedToDelegateTo": {"MSSQLSvc/sql01.corp.example.com:1433"},
	})
	// Credential material in description (ADM-012).
	addUser(sim, base, "bob", "Bob Evans", "bob@corp.example.com", false, map[string][]string{
		"description": {"Onboarding default password1 issued 2024-01-01"},
	})
	// SID history (ADM-013) from a previous domain.
	addUser(sim, base, "legacy", "Legacy Acct", "legacy@corp.example.com", false, map[string][]string{
		"sidHistory": {"S-1-5-21-1000000000-2000000000-3000000000-512"},
	})
	// Nested membership probe (ADM-014): reachable through IT Support → Domain Admins.
	addUser(sim, base, "monitor", "Monitor Service", "monitor@corp.example.com", false)

	addGroup(sim, base, "Domain Admins", "Domain Admins", true, []string{
		"CN=Administrator,CN=Users," + base,
		"CN=IT Support,CN=Users," + base,
	})
	addGroup(sim, base, "Backup Operators", "Backup Operators", true, []string{
		"CN=svc-backup,CN=Users," + base,
	})
	addGroup(sim, base, "Employees", "Employees", false, []string{
		"CN=jdoe,CN=Users," + base,
	})
	addGroup(sim, base, "IT Support", "IT Support", false, []string{
		"CN=Monitor Service,CN=Users," + base,
	})

	sim.Add(&transport.Entry{DN: "OU=IT," + base, Attributes: map[string][]string{
		"objectClass": {"organizationalUnit"}, "objectCategory": {"organizationalUnit"},
		"ou": {"IT"}, "name": {"IT"}, "distinguishedName": {"OU=IT," + base},
		"gPLink": {"[LDAP://CN={A1B2C3D4-E5F6-7890-ABCD-EF1234567890},CN=Policies,CN=System," + base + ";0]"},
	}})
	sim.Add(&transport.Entry{DN: "OU=Domain Controllers," + base, Attributes: map[string][]string{
		"objectClass": {"organizationalUnit"}, "objectCategory": {"organizationalUnit"},
		"ou": {"Domain Controllers"}, "name": {"Domain Controllers"},
		"distinguishedName": {"OU=Domain Controllers," + base},
		"gPLink":            {"[LDAP://CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System," + base + ";0]"},
	}})

	// Group Policy objects (AUTH-003): Default Domain Controllers Policy is
	// linked to the privileged Domain Controllers OU.
	sim.Add(&transport.Entry{DN: "CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System," + base, Attributes: map[string][]string{
		"objectClass": {"groupPolicyContainer"}, "objectCategory": {"gpo"},
		"cn":                {"{6AC1786C-016F-11D2-945F-00C04fB984F9}"},
		"name":              {"Default Domain Controllers Policy"},
		"displayName":       {"Default Domain Controllers Policy"},
		"distinguishedName": {"CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System," + base},
		"gPCFileSysPath":    {`\\corp.example.com\SysVol\corp.example.com\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}`},
	}})
	sim.Add(&transport.Entry{DN: "CN={A1B2C3D4-E5F6-7890-ABCD-EF1234567890},CN=Policies,CN=System," + base, Attributes: map[string][]string{
		"objectClass": {"groupPolicyContainer"}, "objectCategory": {"gpo"},
		"cn":                {"{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"},
		"name":              {"Custom LAPS Policy"},
		"displayName":       {"Custom LAPS Policy"},
		"distinguishedName": {"CN={A1B2C3D4-E5F6-7890-ABCD-EF1234567890},CN=Policies,CN=System," + base},
		"gPCFileSysPath":    {`\\corp.example.com\SysVol\corp.example.com\Policies\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}`},
	}})

	// Computers: FILESRV (unconstrained delegation + risky SPN, LAPS-managed),
	// WEBAPP (RBCD, no LAPS → AUTH-002), WEB01 (clean, LAPS-managed).
	addComputer(sim, base, "FILESRV", "filesrv.corp.example.com", "528384", map[string][]string{ // WORKSTATION_TRUST_ACCOUNT | TRUSTED_FOR_DELEGATION
		"servicePrincipalName":        {"MSSQLSvc/filesrv.corp.example.com:1433"},
		"ms-Mcs-AdmPwdExpirationTime": {"133000000000000000"},
	})
	addComputer(sim, base, "WEBAPP", "webapp.corp.example.com", "4096", map[string][]string{
		"msDS-AllowedToActOnBehalfOfOtherIdentity": {"CN=svc-web,CN=Users,DC=corp,DC=example,DC=com"},
	})
	addComputer(sim, base, "WEB01", "web01.corp.example.com", "4096", map[string][]string{
		"ms-Mcs-AdmPwdExpirationTime": {"133000000000000000"},
	})

	// Trust to an external domain (unfiltered, security-relevant).
	sim.Add(&transport.Entry{DN: "CN=corp,CN=System," + base, Attributes: map[string][]string{
		"objectClass": {"trustedDomain"}, "objectCategory": {"trustedDomain"},
		"cn": {"external.example.net"}, "name": {"external.example.net"},
		"distinguishedName": {"CN=external.example.net,CN=System," + base},
		"trustDirection":    {"2"}, "trustType": {"2"}, "trustAttributes": {"0"},
	}})

	return sim
}

func addUser(sim *Simulator, base, sam, name, upn string, admin bool, extra ...map[string][]string) {
	attrs := map[string][]string{
		"objectClass": {"user"}, "objectCategory": {"CN=Person,CN=Schema,CN=Configuration," + base},
		"cn": {name}, "name": {name},
		"sAMAccountName": {sam}, "distinguishedName": {"CN=" + name + ",CN=Users," + base},
		"userAccountControl": {"512"},
	}
	if upn != "" {
		attrs["userPrincipalName"] = []string{upn}
	}
	switch sam {
	case "kpreauth":
		attrs["userAccountControl"] = []string{"4194816"} // DONT_REQUIRE_PREAUTH
	case "svc-backup":
		attrs["adminCount"] = []string{"1"}
		attrs["description"] = []string{"Backup service account"}
	}
	if admin {
		attrs["adminCount"] = []string{"1"}
	}
	for _, ex := range extra {
		for k, v := range ex {
			attrs[k] = v
		}
	}
	sim.Add(&transport.Entry{DN: "CN=" + name + ",CN=Users," + base, Attributes: attrs})
}

func addGroup(sim *Simulator, base, sam, name string, _ bool, members []string) {
	attrs := map[string][]string{
		"objectClass": {"group"}, "objectCategory": {"group"},
		"cn": {name}, "name": {name}, "sAMAccountName": {sam},
		"distinguishedName": {"CN=" + name + ",CN=Users," + base},
		"groupType":         {"-2147483646"},
	}
	attrs["member"] = append(attrs["member"], members...)
	sim.Add(&transport.Entry{DN: "CN=" + name + ",CN=Users," + base, Attributes: attrs})
}

func addComputer(sim *Simulator, base, name, dns string, uac string, extra map[string][]string) {
	attrs := map[string][]string{
		"objectClass": {"computer", "user"}, "objectCategory": {"computer"},
		"cn": {name}, "name": {name}, "sAMAccountName": {name + "$"},
		"distinguishedName":  {"CN=" + name + ",CN=Computers," + base},
		"operatingSystem":    {"Windows Server 2022"},
		"dNSHostName":        {dns},
		"userAccountControl": {uac},
	}
	for k, v := range extra {
		attrs[k] = v
	}
	sim.Add(&transport.Entry{DN: "CN=" + name + ",CN=Computers," + base, Attributes: attrs})
}

// DemoEndpoint returns a canonical endpoint label for the demo fixture.
func DemoEndpoint() string { return fmt.Sprintf("sim://%s", "corp.example.com") }
