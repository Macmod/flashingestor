package builder

import gildap "github.com/Macmod/flashingestor/ldap"

// BuildAIACAFromEntry constructs an AIACA object from an LDAP entry.
func BuildAIACAFromEntry(entry *gildap.LDAPEntry) (*AIACA, bool) {
	var baseObj BaseADObject
	baseObj.FromEntry(entry, "certification-authority")

	var baseProps BaseProperties
	baseProps.FromEntry(entry)
	baseProps.SetOwnerRightsFlags(baseObj.Aces)

	displayName := entry.GetAttrVal("name", "")
	if displayName == "" {
		displayName = "UNKNOWN"
	}

	aiaca := &AIACA{
		BaseADObject: baseObj,
		Properties: AIACAProperties{
			BaseProperties: baseProps,
			Name:           displayName + "@" + baseProps.Domain,
		},
	}

	// CrossCertificatePair
	crossCertPair := entry.GetAttrRawVal("crossCertificatePair", nil)
	if crossCertPair != nil {
		aiaca.Properties.CrossCertificatePair = crossCertPair
		aiaca.Properties.HasCrossCertificatePair = len(crossCertPair) > 0
	}

	// Certificate - using cACertificate attribute
	certData := entry.GetAttrRawVal("cACertificate", nil)
	if certInfo := parseCACertificate(certData); certInfo != nil {
		aiaca.Properties.CertThumbprint = certInfo.Thumbprint
		aiaca.Properties.CertName = certInfo.Name
		aiaca.Properties.CertChain = certInfo.Chain
		aiaca.Properties.HasBasicConstraints = certInfo.HasBasicConstraints
		aiaca.Properties.BasicConstraintPathLength = certInfo.BasicConstraintPathLength
	}

	return aiaca, true
}
