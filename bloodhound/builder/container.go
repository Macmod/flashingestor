package builder

import (
	"fmt"
	"strings"

	gildap "github.com/Macmod/flashingestor/ldap"
)

// IsFilteredContainer checks if a container DN should be filtered out.
func IsFilteredContainer(containerDN string) bool {
	if containerDN == "" {
		return true
	}

	dn := strings.ToUpper(containerDN)
	if strings.Contains(dn, "CN=DOMAINUPDATES,CN=SYSTEM,DC=") {
		return true
	}
	if strings.Contains(dn, "CN=POLICIES,CN=SYSTEM,DC=") &&
		(strings.HasPrefix(dn, "CN=USER") || strings.HasPrefix(dn, "CN=MACHINE")) {
		return true
	}
	return false
}

// BuildContainerFromEntry constructs a Container object from an LDAP entry.
func BuildContainerFromEntry(entry *gildap.LDAPEntry) (*Container, bool) {
	guid := entry.GetGUID()
	if guid == "" {
		return nil, false
	}

	var baseObj BaseADObject
	baseObj.FromEntry(entry, "container")

	var baseProps BaseProperties
	baseProps.FromEntry(entry)
	baseProps.SetOwnerRightsFlags(baseObj.Aces)

	var containerName string
	if name := entry.GetAttrVal("name", ""); name != "" {
		containerName = fmt.Sprintf("%s@%s", strings.ToUpper(name), baseProps.Domain)
	} else if cn := entry.GetAttrVal("cn", ""); cn != "" {
		containerName = fmt.Sprintf("%s@%s", strings.ToUpper(cn), baseProps.Domain)
	} else {
		containerName = fmt.Sprintf("UNKNOWN@%s", baseProps.Domain)
	}

	container := &Container{
		BaseADObject: baseObj,
		Properties: ContainerProperties{
			BaseProperties: baseProps,
			Name:           containerName,
		},
		ChildObjects: []TypedPrincipal{},
	}

	// Extended properties
	container.Properties.IsACLProtected = container.IsACLProtected

	// --- Child Entries ---
	childEntries, ok := BState().ChildCache.GetChildren(entry.DN)
	if ok {
		for _, child := range childEntries {
			container.ChildObjects = append(container.ChildObjects, child.ToTypedPrincipal())
		}
	}

	// --- Populate InheritanceHashes ---
	securityDescriptor := entry.GetAttrRawVal("nTSecurityDescriptor", nil)
	container.InheritanceHashes = GetInheritedAceHashes(securityDescriptor)

	return container, true
}
