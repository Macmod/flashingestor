package builder

import gildap "github.com/Macmod/flashingestor/ldap"

// BuildEnterpriseCAFromEntry constructs an EnterpriseCA object from an LDAP entry.
func BuildEnterpriseCAFromEntry(entry *gildap.LDAPEntry) (*EnterpriseCA, bool) {
	var baseObj BaseADObject
	baseObj.FromEntry(entry, "certification-authority")

	var baseProps BaseProperties
	baseProps.FromEntry(entry)
	baseProps.SetOwnerRightsFlags(baseObj.Aces)

	displayName := entry.GetAttrVal("name", "")
	if displayName == "" {
		displayName = "UNKNOWN"
	}

	enterpriseCA := &EnterpriseCA{
		BaseADObject: baseObj,
		Properties: EnterpriseCAProperties{
			BaseProperties: baseProps,
			Name:           displayName + "@" + baseProps.Domain,
		},
	}

	// CA-specific properties
	enterpriseCA.Properties.CAName = entry.GetAttrVal("name", "")
	enterpriseCA.Properties.DNSHostname = entry.GetAttrVal("dNSHostName", "")

	// Flags parsing
	flags := parseUint32(entry.GetAttrVal("flags", "0"))
	enterpriseCA.Properties.Flags = parseFlagsToString(flags, certificateAuthorityFlagDefinitions)

	// Certificate - using cACertificate attribute
	certData := entry.GetAttrRawVal("cACertificate", nil)
	if certInfo := ParseCACertificate(certData); certInfo != nil {
		enterpriseCA.Properties.CertThumbprint = certInfo.Thumbprint
		enterpriseCA.Properties.CertName = certInfo.Name
		enterpriseCA.Properties.CertChain = certInfo.Chain
		enterpriseCA.Properties.HasBasicConstraints = certInfo.HasBasicConstraints
		enterpriseCA.Properties.BasicConstraintPathLength = certInfo.BasicConstraintPathLength
	}

	certTemplates := entry.GetAttrVals("certificateTemplates", []string{})

	var enabledCertTemplates []TypedPrincipal
	var unresolvedCertTemplates []string

	for _, templateCN := range certTemplates {
		templateEntry, ok := BState().CertTemplateCache.Get(baseProps.Domain + "+" + templateCN)
		if ok {
			enabledCertTemplates = append(enabledCertTemplates, templateEntry.ToTypedPrincipal())
		} else {
			unresolvedCertTemplates = append(unresolvedCertTemplates, templateCN)
		}
	}

	enterpriseCA.EnabledCertTemplates = enabledCertTemplates
	enterpriseCA.Properties.UnresolvedPublishedTemplates = unresolvedCertTemplates

	// CARegistryData, HttpEnrollmentEndpoints & HostingComputer
	// are only collected in the RemoteCollect phase, so they are not set here.

	return enterpriseCA, true
}
