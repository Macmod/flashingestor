package builder

import (
	"strconv"
	"strings"

	gildap "github.com/Macmod/flashingestor/ldap"
)

// Common OID constants for certificate authentication
const (
	OIDAnyPurpose                 = "2.5.29.37.0"
	OIDClientAuthentication       = "1.3.6.1.5.5.7.3.2"
	OIDPKINITClientAuthentication = "1.3.6.1.5.2.3.4"
	OIDSmartcardLogon             = "1.3.6.1.4.1.311.20.2.2"
	OIDCertificateRequestAgent    = "1.3.6.1.4.1.311.20.2.1"
)

var (
	// AuthenticationOIDs contains OIDs that enable authentication
	AuthenticationOIDs = []string{
		OIDClientAuthentication,
		OIDPKINITClientAuthentication,
		OIDSmartcardLogon,
		OIDAnyPurpose,
	}

	// SchannelAuthenticationOIDs contains OIDs that enable Schannel authentication
	SchannelAuthenticationOIDs = []string{
		OIDClientAuthentication,
		OIDAnyPurpose,
	}
)

// PKIPrivateKeyFlag constants
const (
	PKIPrivateKeyFlagUseLegacyProvider = 0x00000100
)

// PKIEnrollmentFlag constants
const (
	PKIEnrollmentFlagIncludeSymmetricAlgorithms                               = 0x00000001
	PKIEnrollmentFlagPendAllRequests                                          = 0x00000002
	PKIEnrollmentFlagPublishToKRAContainer                                    = 0x00000004
	PKIEnrollmentFlagPublishToDS                                              = 0x00000008
	PKIEnrollmentFlagAutoEnrollmentCheckUserDSCertificate                     = 0x00000010
	PKIEnrollmentFlagAutoEnrollment                                           = 0x00000020
	PKIEnrollmentFlagCTFlagDomainAuthenticationNotRequired                    = 0x00000080
	PKIEnrollmentFlagPreviousApprovalValidateReenrollment                     = 0x00000040
	PKIEnrollmentFlagUserInteractionRequired                                  = 0x00000100
	PKIEnrollmentFlagAddTemplateName                                          = 0x00000200
	PKIEnrollmentFlagRemoveInvalidCertificateFromPersonalStore                = 0x00000400
	PKIEnrollmentFlagAllowEnrollOnBehalfOf                                    = 0x00000800
	PKIEnrollmentFlagAddOCSPNoCheck                                           = 0x00001000
	PKIEnrollmentFlagEnableKeyReuseOnNTTokenKeysetStorageFull                 = 0x00002000
	PKIEnrollmentFlagNoRevocationInfoInIssuedCerts                            = 0x00004000
	PKIEnrollmentFlagIncludeBasicConstraintsForEECerts                        = 0x00008000
	PKIEnrollmentFlagAllowPreviousApprovalKeyBasedRenewalValidateReenrollment = 0x00010000
	PKIEnrollmentFlagIssuancePoliciesFromRequest                              = 0x00020000
	PKIEnrollmentFlagSkipAutoRenewal                                          = 0x00040000
	PKIEnrollmentFlagNoSecurityExtension                                      = 0x00080000
)

// PKICertificateNameFlag constants
const (
	PKICertificateNameFlagEnrolleeSuppliesSubject          = 0x00000001
	PKICertificateNameFlagAddEmail                         = 0x00000002
	PKICertificateNameFlagAddObjGuid                       = 0x00000004
	PKICertificateNameFlagOldCertSuppliesSubjectAndAltName = 0x00000008
	PKICertificateNameFlagAddDirectoryPath                 = 0x00000100
	PKICertificateNameFlagEnrolleeSuppliesSubjectAltName   = 0x00010000
	PKICertificateNameFlagSubjectAltRequireDomainDNS       = 0x00400000
	PKICertificateNameFlagSubjectAltRequireSPN             = 0x00800000
	PKICertificateNameFlagSubjectAltRequireDirectoryGuid   = 0x01000000
	PKICertificateNameFlagSubjectAltRequireUPN             = 0x02000000
	PKICertificateNameFlagSubjectAltRequireEmail           = 0x04000000
	PKICertificateNameFlagSubjectAltRequireDNS             = 0x08000000
	PKICertificateNameFlagSubjectRequireDNSAsCN            = 0x10000000
	PKICertificateNameFlagSubjectRequireEmail              = 0x20000000
	PKICertificateNameFlagSubjectRequireCommonName         = 0x40000000
	PKICertificateNameFlagSubjectRequireDirectoryPath      = 0x80000000
)

// PKICertificateAuthorityFlags constants
const (
	PKICertificateAuthorityFlagNoTemplateSupport              = 0x00000001
	PKICertificateAuthorityFlagSupportsNTAuthentication       = 0x00000002
	PKICertificateAuthorityFlagCASupportsManualAuthentication = 0x00000004
	PKICertificateAuthorityFlagCAServerTypeAdvanced           = 0x00000008
)

// flagDefinition represents a single flag with its value and name
type flagDefinition struct {
	value uint32
	name  string
}

func parseUint32(b string) uint32 {
	if len(b) == 0 {
		return 0
	}

	v, err := strconv.ParseInt(b, 10, 32)
	if err == nil {
		return uint32(v)
	} else {
		return uint32(0)
	}
}

// parseFlagsToString converts a flag value into a comma-separated string of flag names
func parseFlagsToString(flagValue uint32, definitions []flagDefinition) string {
	var flagNames []string
	for _, def := range definitions {
		if (flagValue & def.value) == def.value {
			flagNames = append(flagNames, def.name)
		}
	}
	return strings.Join(flagNames, ", ")
}

// enrollmentFlagDefinitions defines all PKIEnrollmentFlag values
var enrollmentFlagDefinitions = []flagDefinition{
	{PKIEnrollmentFlagIncludeSymmetricAlgorithms, "INCLUDE_SYMMETRIC_ALGORITHMS"},
	{PKIEnrollmentFlagPendAllRequests, "PEND_ALL_REQUESTS"},
	{PKIEnrollmentFlagPublishToKRAContainer, "PUBLISH_TO_KRA_CONTAINER"},
	{PKIEnrollmentFlagPublishToDS, "PUBLISH_TO_DS"},
	{PKIEnrollmentFlagAutoEnrollmentCheckUserDSCertificate, "AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE"},
	{PKIEnrollmentFlagAutoEnrollment, "AUTO_ENROLLMENT"},
	{PKIEnrollmentFlagCTFlagDomainAuthenticationNotRequired, "CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED"},
	{PKIEnrollmentFlagPreviousApprovalValidateReenrollment, "PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT"},
	{PKIEnrollmentFlagUserInteractionRequired, "USER_INTERACTION_REQUIRED"},
	{PKIEnrollmentFlagAddTemplateName, "ADD_TEMPLATE_NAME"},
	{PKIEnrollmentFlagRemoveInvalidCertificateFromPersonalStore, "REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE"},
	{PKIEnrollmentFlagAllowEnrollOnBehalfOf, "ALLOW_ENROLL_ON_BEHALF_OF"},
	{PKIEnrollmentFlagAddOCSPNoCheck, "ADD_OCSP_NOCHECK"},
	{PKIEnrollmentFlagEnableKeyReuseOnNTTokenKeysetStorageFull, "ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL"},
	{PKIEnrollmentFlagNoRevocationInfoInIssuedCerts, "NOREVOCATIONINFOINISSUEDCERTS"},
	{PKIEnrollmentFlagIncludeBasicConstraintsForEECerts, "INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS"},
	{PKIEnrollmentFlagAllowPreviousApprovalKeyBasedRenewalValidateReenrollment, "ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT"},
	{PKIEnrollmentFlagIssuancePoliciesFromRequest, "ISSUANCE_POLICIES_FROM_REQUEST"},
	{PKIEnrollmentFlagSkipAutoRenewal, "SKIP_AUTO_RENEWAL"},
	{PKIEnrollmentFlagNoSecurityExtension, "NO_SECURITY_EXTENSION"},
}

// certificateNameFlagDefinitions defines all PKICertificateNameFlag values
var certificateNameFlagDefinitions = []flagDefinition{
	{PKICertificateNameFlagEnrolleeSuppliesSubject, "ENROLLEE_SUPPLIES_SUBJECT"},
	{PKICertificateNameFlagAddEmail, "ADD_EMAIL"},
	{PKICertificateNameFlagAddObjGuid, "ADD_OBJ_GUID"},
	{PKICertificateNameFlagOldCertSuppliesSubjectAndAltName, "OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME"},
	{PKICertificateNameFlagAddDirectoryPath, "ADD_DIRECTORY_PATH"},
	{PKICertificateNameFlagEnrolleeSuppliesSubjectAltName, "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME"},
	{PKICertificateNameFlagSubjectAltRequireDomainDNS, "SUBJECT_ALT_REQUIRE_DOMAIN_DNS"},
	{PKICertificateNameFlagSubjectAltRequireSPN, "SUBJECT_ALT_REQUIRE_SPN"},
	{PKICertificateNameFlagSubjectAltRequireDirectoryGuid, "SUBJECT_ALT_REQUIRE_DIRECTORY_GUID"},
	{PKICertificateNameFlagSubjectAltRequireUPN, "SUBJECT_ALT_REQUIRE_UPN"},
	{PKICertificateNameFlagSubjectAltRequireEmail, "SUBJECT_ALT_REQUIRE_EMAIL"},
	{PKICertificateNameFlagSubjectAltRequireDNS, "SUBJECT_ALT_REQUIRE_DNS"},
	{PKICertificateNameFlagSubjectRequireDNSAsCN, "SUBJECT_REQUIRE_DNS_AS_CN"},
	{PKICertificateNameFlagSubjectRequireEmail, "SUBJECT_REQUIRE_EMAIL"},
	{PKICertificateNameFlagSubjectRequireCommonName, "SUBJECT_REQUIRE_COMMON_NAME"},
	{PKICertificateNameFlagSubjectRequireDirectoryPath, "SUBJECT_REQUIRE_DIRECTORY_PATH"},
}

// certificateAuthorityFlagDefinitions defines all PKICertificateAuthorityFlag values
var certificateAuthorityFlagDefinitions = []flagDefinition{
	{PKICertificateAuthorityFlagNoTemplateSupport, "NO_TEMPLATE_SUPPORT"},
	{PKICertificateAuthorityFlagSupportsNTAuthentication, "SUPPORTS_NT_AUTHENTICATION"},
	{PKICertificateAuthorityFlagCASupportsManualAuthentication, "CA_SUPPORTS_MANUAL_AUTHENTICATION"},
	{PKICertificateAuthorityFlagCAServerTypeAdvanced, "CA_SERVERTYPE_ADVANCED"},
}

// BuildCertTemplateFromEntry converts an LDAP entry into a CertTemplate structure.
// BuildCertTemplateFromEntry constructs a CertTemplate object from an LDAP entry.
func BuildCertTemplateFromEntry(entry *gildap.LDAPEntry) (*CertTemplate, bool) {
	var baseObj BaseADObject
	baseObj.FromEntry(entry, "pki-certificate-template")

	var baseProps BaseProperties
	baseProps.FromEntry(entry)

	displayName := entry.GetAttrVal("name", "")
	if displayName == "" {
		displayName = "UNKNOWN"
	}

	certTemplate := &CertTemplate{
		BaseADObject: baseObj,
		Properties: CertTemplateProperties{
			BaseProperties: baseProps,
			Name:           displayName,
		},
	}

	// Parse validity and renewal periods
	certTemplate.Properties.ValidityPeriod = ConvertPKIPeriod(entry.GetAttrRawVal("pKIExpirationPeriod", nil))
	certTemplate.Properties.RenewalPeriod = ConvertPKIPeriod(entry.GetAttrRawVal("pKIOverlapPeriod", nil))

	// Schema version
	schemaVersionStr := entry.GetAttrVal("msPKI-Template-Schema-Version", "0")
	schemaVersion := parseUint32(schemaVersionStr)
	certTemplate.Properties.SchemaVersion = schemaVersion

	certTemplate.Properties.DisplayName = entry.GetAttrVal("displayName", "")
	certTemplate.Properties.OID = entry.GetAttrVal("msPKI-Cert-Template-OID", "")

	// Enrollment flags
	enrollmentFlag := parseUint32(entry.GetAttrVal("msPKI-Enrollment-Flag", "0"))
	certTemplate.Properties.EnrollmentFlag = parseFlagsToString(enrollmentFlag, enrollmentFlagDefinitions)
	certTemplate.Properties.RequiresManagerApproval = (enrollmentFlag & PKIEnrollmentFlagPendAllRequests) == PKIEnrollmentFlagPendAllRequests
	certTemplate.Properties.NoSecurityExtension = (enrollmentFlag & PKIEnrollmentFlagNoSecurityExtension) == PKIEnrollmentFlagNoSecurityExtension

	// Name flags
	nameFlag := parseUint32(entry.GetAttrVal("msPKI-Certificate-Name-Flag", "0"))
	certTemplate.Properties.CertificateNameFlag = parseFlagsToString(nameFlag, certificateNameFlagDefinitions)
	certTemplate.Properties.EnrolleeSuppliesSubject = (nameFlag & PKICertificateNameFlagEnrolleeSuppliesSubject) == PKICertificateNameFlagEnrolleeSuppliesSubject
	certTemplate.Properties.SubjectAltRequireUPN = (nameFlag & PKICertificateNameFlagSubjectAltRequireUPN) == PKICertificateNameFlagSubjectAltRequireUPN
	certTemplate.Properties.SubjectAltRequireDNS = (nameFlag & PKICertificateNameFlagSubjectAltRequireDNS) == PKICertificateNameFlagSubjectAltRequireDNS
	certTemplate.Properties.SubjectAltRequireDomainDNS = (nameFlag & PKICertificateNameFlagSubjectAltRequireDomainDNS) == PKICertificateNameFlagSubjectAltRequireDomainDNS
	certTemplate.Properties.SubjectAltRequireEmail = (nameFlag & PKICertificateNameFlagSubjectAltRequireEmail) == PKICertificateNameFlagSubjectAltRequireEmail
	certTemplate.Properties.SubjectAltRequireSPN = (nameFlag & PKICertificateNameFlagSubjectAltRequireSPN) == PKICertificateNameFlagSubjectAltRequireSPN
	certTemplate.Properties.SubjectRequireEmail = (nameFlag & PKICertificateNameFlagSubjectRequireEmail) == PKICertificateNameFlagSubjectRequireEmail

	// EKUs and policies
	certTemplate.Properties.EKUs = entry.GetAttrVals("pKIExtendedKeyUsage", []string{})
	certTemplate.Properties.CertificateApplicationPolicy = entry.GetAttrVals("msPKI-Certificate-Application-Policy", []string{})
	certTemplate.Properties.CertificatePolicy = entry.GetAttrVals("msPKI-Certificate-Policy", []string{})

	// Authorized signatures
	authSigStr := entry.GetAttrVal("msPKI-RA-Signature", "0")
	var authSig int64
	for _, c := range authSigStr {
		if c >= '0' && c <= '9' {
			authSig = authSig*10 + int64(c-'0')
		}
	}
	certTemplate.Properties.AuthorizedSignatures = authSig

	// Check for legacy provider flag
	privateKeyFlag := parseUint32(entry.GetAttrVal("msPKI-Private-Key-Flag", "0"))
	hasUseLegacyProvider := (privateKeyFlag & PKIPrivateKeyFlagUseLegacyProvider) != 0

	// Application policies
	rawApplicationPolicies := entry.GetAttrVals("msPKI-Certificate-Application-Policy", []string{})
	certTemplate.Properties.ApplicationPolicies = ParseCertTemplateApplicationPolicies(
		rawApplicationPolicies,
		int(schemaVersion),
		hasUseLegacyProvider,
	)

	certTemplate.Properties.IssuancePolicies = entry.GetAttrVals("msPKI-RA-Application-Policies", []string{})

	// Effective EKUs
	if schemaVersion == 1 && len(certTemplate.Properties.EKUs) > 0 {
		certTemplate.Properties.EffectiveEKUs = certTemplate.Properties.EKUs
	} else {
		certTemplate.Properties.EffectiveEKUs = certTemplate.Properties.CertificateApplicationPolicy
	}

	// Authentication enabled - check if any effective EKU intersects with authentication OIDs
	certTemplate.Properties.AuthenticationEnabled = len(certTemplate.Properties.EffectiveEKUs) == 0 ||
		hasOIDIntersection(certTemplate.Properties.EffectiveEKUs, AuthenticationOIDs)

	// Schannel authentication enabled - check if any effective EKU intersects with Schannel OIDs
	certTemplate.Properties.SchannelAuthenticationEnabled = len(certTemplate.Properties.EffectiveEKUs) == 0 ||
		hasOIDIntersection(certTemplate.Properties.EffectiveEKUs, SchannelAuthenticationOIDs)

	return certTemplate, true
}

// ParseCertTemplateApplicationPolicies parses application policies based on schema version
// Format: "Name`Type`Value`Name`Type`Value`..."
// (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/c55ec697-be3f-4117-8316-8895e4399237)
// Returns the Value of Name = "msPKI-RA-Application-Policies" entries
func ParseCertTemplateApplicationPolicies(applicationPolicies []string, schemaVersion int, hasUseLegacyProvider bool) []string {
	if len(applicationPolicies) == 0 ||
		schemaVersion == 1 ||
		schemaVersion == 2 ||
		(schemaVersion == 4 && hasUseLegacyProvider) {
		return applicationPolicies
	}

	// Parse the backtick-delimited format
	if len(applicationPolicies) == 0 {
		return []string{}
	}

	entries := strings.Split(applicationPolicies[0], "`")
	var result []string

	// Group entries into triplets (Name, Type, Value)
	for i := 0; i+2 < len(entries); i += 3 {
		name := entries[i]
		// type := entries[i+1]  // Not used in the filter
		value := entries[i+2]

		// Filter for msPKI-RA-Application-Policies entries (case-insensitive)
		if strings.EqualFold(name, "msPKI-RA-Application-Policies") {
			result = append(result, value)
		}
	}

	return result
}

// hasOIDIntersection checks if any OID in the first slice exists in the second slice
func hasOIDIntersection(oids1 []string, oids2 []string) bool {
	for _, oid1 := range oids1 {
		for _, oid2 := range oids2 {
			if oid1 == oid2 {
				return true
			}
		}
	}
	return false
}

// ConvertPKIPeriod converts PKI period bytes to a human-readable string
// The bytes represent a 64-bit integer in little-endian format representing 100-nanosecond intervals
func ConvertPKIPeriod(bytes []byte) string {
	if len(bytes) == 0 {
		return "Unknown"
	}

	// Reverse bytes (convert from little-endian to big-endian for parsing)
	reversed := make([]byte, len(bytes))
	copy(reversed, bytes)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}

	// Convert bytes to int64
	var value int64
	for _, b := range reversed {
		value = value<<8 | int64(b)
	}

	// Multiply by -0.0000001 to get seconds (PKI periods are stored as negative 100-nanosecond intervals)
	seconds := float64(value) * -0.0000001

	// Check for years (31536000 seconds = 365 days)
	if int64(seconds)%31536000 == 0 && seconds/31536000 >= 1 {
		years := int64(seconds / 31536000)
		if years == 1 {
			return "1 year"
		}
		return formatPeriod(years, "years")
	}

	// Check for months (2592000 seconds = 30 days)
	if int64(seconds)%2592000 == 0 && seconds/2592000 >= 1 {
		months := int64(seconds / 2592000)
		if months == 1 {
			return "1 month"
		}
		return formatPeriod(months, "months")
	}

	// Check for weeks (604800 seconds = 7 days)
	if int64(seconds)%604800 == 0 && seconds/604800 >= 1 {
		weeks := int64(seconds / 604800)
		if weeks == 1 {
			return "1 week"
		}
		return formatPeriod(weeks, "weeks")
	}

	// Check for days (86400 seconds = 24 hours)
	if int64(seconds)%86400 == 0 && seconds/86400 >= 1 {
		days := int64(seconds / 86400)
		if days == 1 {
			return "1 day"
		}
		return formatPeriod(days, "days")
	}

	// Check for hours (3600 seconds = 1 hour)
	if int64(seconds)%3600 == 0 && seconds/3600 >= 1 {
		hours := int64(seconds / 3600)
		if hours == 1 {
			return "1 hour"
		}
		return formatPeriod(hours, "hours")
	}

	return ""
}

// formatPeriod formats a period value with its unit
func formatPeriod(value int64, unit string) string {
	return strings.Join([]string{formatInt64(value), unit}, " ")
}

// formatInt64 converts an int64 to string
func formatInt64(n int64) string {
	if n == 0 {
		return "0"
	}

	negative := n < 0
	if negative {
		n = -n
	}

	var result []byte
	for n > 0 {
		result = append(result, byte('0'+n%10))
		n /= 10
	}

	// Reverse the result
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	if negative {
		return "-" + string(result)
	}
	return string(result)
}
