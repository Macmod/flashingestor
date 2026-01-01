package builder

import gildap "github.com/Macmod/flashingestor/ldap"

// BuildIssuancePolicyFromEntry constructs an IssuancePolicy object from an LDAP entry.
func BuildIssuancePolicyFromEntry(entry *gildap.LDAPEntry) (*IssuancePolicy, bool) {
	var baseObj BaseADObject
	baseObj.FromEntry(entry, "ms-pki-enterprise-oid")

	var baseProps BaseProperties
	baseProps.FromEntry(entry)
	baseProps.SetOwnerRightsFlags(baseObj.Aces)

	displayName := entry.GetAttrVal("displayName", "")
	if displayName == "" {
		displayName = entry.GetAttrVal("cn", "")
	}
	if displayName == "" {
		displayName = "UNKNOWN"
	}

	issuancePolicy := &IssuancePolicy{
		BaseADObject: baseObj,
		Properties: IssuancePolicyProperties{
			BaseProperties: baseProps,
			Name:           displayName + "@" + baseProps.Domain,
		},
	}

	// IssuancePolicy-specific properties
	issuancePolicy.Properties.DisplayName = entry.GetAttrVal("displayName", "")
	issuancePolicy.Properties.CertTemplateOID = entry.GetAttrVal("msPKI-Cert-Template-OID", "")

	// OID Group Link
	oidGroupLink := entry.GetAttrVal("msPKI-OID-Group-Link", "")
	if oidGroupLink != "" {
		// Resolve the DN to get the typed principal
		if resolvedEntry, exists := BState().MemberCache.Get(oidGroupLink); exists {
			linkedGroup := resolvedEntry.ToTypedPrincipal()
			issuancePolicy.Properties.OIDGroupLink = linkedGroup.ObjectIdentifier
			issuancePolicy.GroupLink = linkedGroup
		}
	}

	return issuancePolicy, true
}
