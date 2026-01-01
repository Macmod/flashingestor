package builder

import (
	"strings"

	gildap "github.com/Macmod/flashingestor/ldap"
)

// BuildGPOFromEntry constructs a GPO object from an LDAP entry.
func BuildGPOFromEntry(entry *gildap.LDAPEntry) (*GPO, bool) {
	var baseObj BaseADObject
	baseObj.FromEntry(entry, "group-policy-container")

	var baseProps BaseProperties
	baseProps.FromEntry(entry)
	baseProps.SetOwnerRightsFlags(baseObj.Aces)

	guid := entry.GetGUID()
	if guid == "" {
		return nil, false
	}

	gpoName := strings.ToUpper(entry.GetAttrVal("displayName", "")) + "@" + strings.ToUpper(baseProps.Domain)

	gpo := &GPO{
		BaseADObject: baseObj,
		Properties: GPOProperties{
			BaseProperties: baseProps,
			Name:           gpoName,
			HighValue:      false,
			GPCPath:        strings.ToUpper(entry.GetAttrVal("gPCFileSysPath", "")),
		},
	}

	gpo.Properties.IsACLProtected = gpo.IsACLProtected

	return gpo, true
}
