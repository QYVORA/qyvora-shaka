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

	sim.Add(&transport.Entry{DN: base, Attributes: map[string][]string{
		"objectClass": {"domain"}, "name": {"corp"}, "distinguishedName": {base},
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

	addGroup(sim, base, "Domain Admins", "Domain Admins", true, []string{
		"CN=Administrator,CN=Users," + base,
	})
	addGroup(sim, base, "Backup Operators", "Backup Operators", true, []string{
		"CN=svc-backup,CN=Users," + base,
	})
	addGroup(sim, base, "Employees", "Employees", false, []string{
		"CN=jdoe,CN=Users," + base,
	})

	sim.Add(&transport.Entry{DN: "OU=IT," + base, Attributes: map[string][]string{
		"objectClass": {"organizationalUnit"}, "objectCategory": {"organizationalUnit"},
		"ou": {"IT"}, "name": {"IT"}, "distinguishedName": {"OU=IT," + base},
	}})
	sim.Add(&transport.Entry{DN: "OU=Domain Controllers," + base, Attributes: map[string][]string{
		"objectClass": {"organizationalUnit"}, "objectCategory": {"organizationalUnit"},
		"ou": {"Domain Controllers"}, "name": {"Domain Controllers"},
		"distinguishedName": {"OU=Domain Controllers," + base},
	}})

	// Trust to an external domain (unfiltered, security-relevant).
	sim.Add(&transport.Entry{DN: "CN=corp,CN=System," + base, Attributes: map[string][]string{
		"objectClass": {"trustedDomain"}, "objectCategory": {"trustedDomain"},
		"cn": {"external.example.net"}, "name": {"external.example.net"},
		"distinguishedName": {"CN=external.example.net,CN=System," + base},
		"trustDirection":    {"2"}, "trustType": {"2"}, "trustAttributes": {"0"},
	}})

	return sim
}

func addUser(sim *Simulator, base, sam, name, upn string, admin bool) {
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

// DemoEndpoint returns a canonical endpoint label for the demo fixture.
func DemoEndpoint() string { return fmt.Sprintf("sim://%s", "corp.example.com") }
