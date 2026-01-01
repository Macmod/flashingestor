package builder

import gildap "github.com/Macmod/flashingestor/ldap"

// BuildRootCAFromEntry constructs a RootCA object from an LDAP entry.
func BuildRootCAFromEntry(entry *gildap.LDAPEntry) (*RootCA, bool) {
	var baseObj BaseADObject
	baseObj.FromEntry(entry, "certification-authority")

	var baseProps BaseProperties
	baseProps.FromEntry(entry)
	baseProps.SetOwnerRightsFlags(baseObj.Aces)

	displayName := entry.GetAttrVal("name", "")
	if displayName == "" {
		displayName = "UNKNOWN"
	}

	domainName := entry.GetDomainFromDN()
	domainSid, ok := BState().DomainSIDCache.Get(domainName)
	if !ok {
		domainSid = ""
	}

	rootca := &RootCA{
		BaseADObject: baseObj,
		DomainSID:    domainSid,
		Properties: RootCAProperties{
			BaseProperties: baseProps,
			Name:           displayName + "@" + baseProps.Domain,
		},
	}

	// Certificate - using cACertificate attribute
	certData := entry.GetAttrRawVal("cACertificate", nil)
	if certInfo := ParseCACertificate(certData); certInfo != nil {
		rootca.Properties.CertThumbprint = certInfo.Thumbprint
		rootca.Properties.CertName = certInfo.Name
		rootca.Properties.CertChain = certInfo.Chain
		rootca.Properties.HasBasicConstraints = certInfo.HasBasicConstraints
		rootca.Properties.BasicConstraintPathLength = certInfo.BasicConstraintPathLength
	}

	return rootca, true
}
