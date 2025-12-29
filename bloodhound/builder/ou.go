package builder

import (
	"strings"

	gildap "github.com/Macmod/flashingestor/ldap"
)

// BuildOUFromEntry constructs an OrganizationalUnit object from an LDAP entry.
func BuildOUFromEntry(entry *gildap.LDAPEntry) (*OrganizationalUnit, bool) {
	var baseObj BaseADObject
	baseObj.FromEntry(entry, "ou")

	var baseProps BaseProperties
	baseProps.FromEntry(entry)
	baseProps.SetOwnerRightsFlags(baseObj.Aces)

	var ouName string
	if name := entry.GetAttrVal("name", ""); name != "" {
		ouName = strings.ToUpper(name) + "@" + baseProps.Domain
	} else if ou := entry.GetAttrVal("ou", ""); ou != "" {
		ouName = strings.ToUpper(ou) + "@" + baseProps.Domain
	} else {
		ouName = "UNKNOWN@" + baseProps.Domain
	}

	ou := &OrganizationalUnit{
		BaseADObject: baseObj,
		Properties: OUProperties{
			BaseProperties:    baseProps,
			Name:              ouName,
			HighValue:         false,
			BlocksInheritance: entry.GetAttrVal("gPOptions", "0") == "1",
		},
		Links:        []GPLinkRef{},
		ChildObjects: []TypedPrincipal{},
		GPOChanges: GPOChangeSet{
			AffectedComputers:  []TypedPrincipal{},
			DcomUsers:          []any{},
			LocalAdmins:        []any{},
			PSRemoteUsers:      []any{},
			RemoteDesktopUsers: []any{},
		},
	}

	// Optional extended properties
	ou.Properties.IsACLProtected = ou.IsACLProtected

	// --- Child Objects ---
	childEntries, ok := BState().ChildCache.GetChildren(entry.DN)
	if ok {
		for _, child := range childEntries {
			ou.ChildObjects = append(ou.ChildObjects, child.ToTypedPrincipal())
		}
	}

	// --- GPO Links ---
	gplinkStr := entry.GetAttrVal("gPLink", "")
	gplinks := ParseGPLinkString(gplinkStr)

	for _, link := range gplinks {
		option := link.Option
		if option == 0 || option == 2 {
			ouLink := GPLinkRef{
				IsEnforced: link.Option == 2,
			}

			entry, ok := BState().MemberCache.Get(link.DN)

			// TODO: Review second condition
			if ok && entry.ObjectIdentifier != "" {
				ouLink.GUID = entry.ObjectIdentifier
				ou.Links = append(ou.Links, ouLink)
			}
		}
	}

	return ou, true
}
