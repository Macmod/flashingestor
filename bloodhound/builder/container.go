package builder

import (
	"fmt"
	"strings"

	gildap "github.com/Macmod/flashingestor/ldap"
)

// buildContainerFromEntry converts an LDAP entry into a Container structure.
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

	return container, true
}
