package builder

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"strings"

	gildap "github.com/Macmod/flashingestor/ldap"
)

// BuildNTAuthStoreFromEntry constructs an NTAuthStore object from an LDAP entry.
func BuildNTAuthStoreFromEntry(entry *gildap.LDAPEntry) (*NTAuthStore, bool) {
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

	ntauthstore := &NTAuthStore{
		BaseADObject: baseObj,
		DomainSID:    domainSid,
		Properties: NTAuthStoreProperties{
			BaseProperties: baseProps,
			Name:           displayName + "@" + baseProps.Domain,
		},
	}

	certs := entry.GetAttrVals("cACertificate", []string{})
	if len(certs) > 0 {
		for _, certData := range certs {
			cert, err := x509.ParseCertificate([]byte(certData))
			if err != nil {
				continue
			}

			hash := sha1.Sum(cert.Raw)
			thumbprint := strings.ToUpper(hex.EncodeToString(hash[:]))

			ntauthstore.Properties.CertThumbprints = append(ntauthstore.Properties.CertThumbprints, thumbprint)
		}
	}
	return ntauthstore, true
}
