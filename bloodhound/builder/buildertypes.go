// Package builder constructs BloodHound-compatible objects from LDAP entries.
// It handles AD principals, PKI infrastructure, and their relationships.
package builder

import (
	"strings"
	"time"

	gildap "github.com/Macmod/flashingestor/ldap"
)

// BaseADObject contains fields shared across most AD principals.
// Embedded in User, Group, Computer, OU, Domain, Container, and GPO.
// JSON marshaling promotes these fields to the outer struct.
type BaseADObject struct {
	ObjectIdentifier string          `json:"ObjectIdentifier"`
	Aces             []ACE           `json:"Aces"`
	IsDeleted        bool            `json:"IsDeleted"`
	IsACLProtected   bool            `json:"IsACLProtected"`
	ContainedBy      *TypedPrincipal `json:"ContainedBy"`
}

func (bo *BaseADObject) FromEntry(entry *gildap.LDAPEntry, entryType string) {
	// Fills common properties for a BaseADObject
	oid := entry.GetSID()
	if oid == "" {
		oid = entry.GetGUID()
	}
	if oid == "" {
		// Fallback to DN
		// Not sure how bloodhound will handle this case, but we do it for completeness
		oid = entry.DN
	}
	bo.ObjectIdentifier = oid

	securityDescriptor := entry.GetAttrRawVal("nTSecurityDescriptor", nil)

	if securityDescriptor == nil {
		BState().EmptySDCount++
	}

	entryDomain := entry.GetDomainFromDN()

	parsedACEs, isACLProtected, err := ParseBinaryACL(
		entryType, entryDomain, entry.HasLAPS(), securityDescriptor,
	)

	if err == nil {
		ResolveACETypes(&parsedACEs, BState().SIDCache, entryDomain)
		bo.Aces = parsedACEs
	}

	bo.IsACLProtected = isACLProtected

	bo.IsDeleted = entry.GetAttrVal("isDeleted", "") == "TRUE"

	if parentEntry, exists := BState().MemberCache.Get(entry.GetParentDN()); exists {
		resolvedObj := parentEntry.ToTypedPrincipal()
		bo.ContainedBy = &resolvedObj
	}
}

// BaseProperties holds common metadata for AD objects.
type BaseProperties struct {
	Domain                              string `json:"domain"`
	DistinguishedName                   string `json:"distinguishedname,omitempty"`
	DomainSID                           string `json:"domainsid,omitempty"`
	Description                         string `json:"description,omitempty"`
	WhenCreated                         int64  `json:"whencreated,omitempty"`
	DoesAnyAceGrantOwnerRights          bool   `json:"doesanyacegrantownerrights"`
	DoesAnyInheritedAceGrantOwnerRights bool   `json:"doesanyinheritedacegrantownerrights"`
}

// FromEntry populates common properties from an LDAP entry.
func (bp *BaseProperties) FromEntry(entry *gildap.LDAPEntry) {
	// These should always be present
	bp.DistinguishedName = strings.ToUpper(entry.DN)
	bp.Domain = entry.GetDomainFromDN()

	// Only a subset of principals include an objectSid attribute that
	// can be mapped to a domain SID.
	// If it doesn't include the attribute, try to find the domain SID by mapping
	// the domain name (extracted from the DN) using the cache.
	domainSid, err := entry.GetDomainSID()
	if err == nil {
		bp.DomainSID = domainSid
	}

	domainSid, ok := BState().DomainSIDCache.Get(bp.Domain)
	if !ok {
		domainSid = ""
	}
	bp.DomainSID = domainSid

	// Map description / whenCreated, if present
	bp.Description = entry.GetAttrVal("description", "")

	whenCreatedStr := entry.GetAttrVal("whenCreated", "")
	if whenCreatedStr == "" {
		bp.WhenCreated = 0
	} else {
		bp.WhenCreated = FormatTime1(whenCreatedStr)
	}
}

func (bp *BaseProperties) SetOwnerRightsFlags(aces []ACE) {
	bp.DoesAnyAceGrantOwnerRights = CheckAnyACEGrantOwnerRights(aces, false)
	bp.DoesAnyInheritedAceGrantOwnerRights = CheckAnyACEGrantOwnerRights(aces, true)
}

func CheckAnyACEGrantOwnerRights(aces []ACE, inherited bool) bool {
	for _, ace := range aces {
		if !inherited && ace.IsPermissionForOwnerRightsSid {
			return true
		} else if inherited && ace.IsInheritedPermissionForOwnerRightsSid {
			return true
		}
	}
	return false
}

// Domain represents an Active Directory domain.
type Domain struct {
	BaseADObject
	Properties           DomainProperties `json:"Properties"`
	Trusts               []DomainTrust    `json:"Trusts"`
	Links                []GPLinkRef      `json:"Links"`
	ChildObjects         []TypedPrincipal `json:"ChildObjects"`
	GPOChanges           GPOChanges       `json:"GPOChanges"`
	InheritanceHashes    []string         `json:"InheritanceHashes"`              // TODO: Fill
	ForestRootIdentifier string           `json:"ForestRootIdentifier,omitempty"` // TODO: Fill
}

// DomainProperties holds metadata about the domain.
type DomainProperties struct {
	BaseProperties
	Name            string `json:"name"`
	FunctionalLevel string `json:"functionallevel"`
	HighValue       bool   `json:"highvalue"` // Not present in sample (?)
	IsACLProtected  bool   `json:"isaclprotected"`
	Collected       bool   `json:"collected"`
}

// DomainTrust represents a trust ACLship between domains.
type DomainTrust struct {
	Name                 string `json:"TargetDomainName"`
	TrustDirection       string `json:"TrustDirection"`
	TrustType            string `json:"TrustType"`
	SecurityID           string `json:"TargetDomainSid"`
	SidFilteringEnabled  bool   `json:"SidFilteringEnabled"`
	IsTransitive         bool   `json:"IsTransitive"`
	TGTDelegationEnabled bool   `json:"TGTDelegationEnabled"`
}

// OrganizationalUnit represents an AD OU with nested properties and linked GPOs.
type OrganizationalUnit struct {
	BaseADObject
	Properties   OUProperties     `json:"Properties"`
	Links        []GPLinkRef      `json:"Links"`
	ChildObjects []TypedPrincipal `json:"ChildObjects"`
	GPOChanges   GPOChanges       `json:"GPOChanges"`
}

// OUProperties contains the OU-specific metadata.
type OUProperties struct {
	BaseProperties
	Name              string `json:"name"`
	IsACLProtected    bool   `json:"isaclprotected"`
	BlocksInheritance bool   `json:"blocksinheritance"`
	HighValue         bool   `json:"highvalue"`
}

// GPOChanges represents GPO-related deltas linked to this OU.
type GPOChanges struct {
	AffectedComputers  []TypedPrincipal `json:"affectedcomputers"`
	DcomUsers          []TypedPrincipal `json:"dcomusers"`
	LocalAdmins        []TypedPrincipal `json:"localadmins"`
	PSRemoteUsers      []TypedPrincipal `json:"psremoteusers"`
	RemoteDesktopUsers []TypedPrincipal `json:"remotedesktopusers"`
}

// GPO represents a Group Policy Object in AD.
type GPO struct {
	BaseADObject
	Properties GPOProperties `json:"Properties"`
}

// GPOProperties contains descriptive and identifying metadata for a GPO.
type GPOProperties struct {
	BaseProperties
	Name           string `json:"name"`
	IsACLProtected bool   `json:"isaclprotected"`
	GPCPath        string `json:"gpcpath"`
	HighValue      bool   `json:"highvalue"`
}

// Container represents an Active Directory container (e.g., CN=Users, CN=Computers).
type Container struct {
	BaseADObject
	Properties   ContainerProperties `json:"Properties"`
	ChildObjects []TypedPrincipal    `json:"ChildObjects"`
}

// ContainerProperties holds AD metadata for the container.
type ContainerProperties struct {
	BaseProperties
	Name           string `json:"name"`
	HighValue      bool   `json:"highvalue"`
	IsACLProtected bool   `json:"isaclprotected"`
}

// User is the top-level object representing an AD user.
type SPNPrivilege struct {
	ComputerSID string `json:"ComputerSID"`
	Port        int    `json:"Port"`
	Service     string `json:"Service"`
}

type User struct {
	BaseADObject
	Properties              UserProperties   `json:"Properties"`
	AllowedToDelegate       []TypedPrincipal `json:"AllowedToDelegate"`
	UnconstrainedDelegation bool             `json:"UnconstrainedDelegation"`
	PrimaryGroupSID         string           `json:"PrimaryGroupSID"`
	HasSIDHistory           []TypedPrincipal `json:"HasSIDHistory"`
	SPNTargets              []SPNPrivilege   `json:"SPNTargets"`
	DomainSID               string           `json:"DomainSID"`
}

// UserProperties holds various extracted attributes.
type UserProperties struct {
	BaseProperties
	Name                    string   `json:"name"`
	SAMAccountName          string   `json:"samaccountname"`
	IsACLProtected          bool     `json:"isaclprotected"`
	Sensitive               bool     `json:"sensitive"`
	DontReqPreauth          bool     `json:"dontreqpreauth"`
	PasswordNotReqd         bool     `json:"passwordnotreqd"`
	UnconstrainedDelegation bool     `json:"unconstraineddelegation"`
	PwdNeverExpires         bool     `json:"pwdneverexpires"`
	Enabled                 bool     `json:"enabled"`
	TrustedToAuth           bool     `json:"trustedtoauth"`
	LastLogon               int64    `json:"lastlogon"`
	LastLogonTimestamp      int64    `json:"lastlogontimestamp"`
	PwdLastSet              int64    `json:"pwdlastset"`
	ServicePrincipalNames   []string `json:"serviceprincipalnames"`
	HasSPN                  bool     `json:"hasspn"`
	DisplayName             string   `json:"displayname"`
	Email                   string   `json:"email"`           // Nullable
	Title                   string   `json:"title"`           // Nullable
	HomeDirectory           string   `json:"homedirectory"`   // Nullable
	UserPassword            string   `json:"userpassword"`    // Nullable
	UnixPassword            string   `json:"unixpassword"`    // Nullable
	UnicodePassword         string   `json:"unicodepassword"` // Nullable
	SFUPassword             string   `json:"sfupassword"`     // Nullable
	LogonScript             string   `json:"logonscript"`     // Nullable
	AllowedToDelegate       []string `json:"allowedtodelegate,omitempty"`
	AdminCount              bool     `json:"admincount"`
	SIDHistory              []string `json:"sidhistory"`
	AdminSDHolderProtected  bool     `json:"adminsdholderprotected"`
}

// Group represents an Active Directory group object.
type Group struct {
	BaseADObject
	HasSIDHistory []TypedPrincipal `json:"HasSIDHistory"`
	Properties    GroupProperties  `json:"Properties"`
	Members       []TypedPrincipal `json:"Members"`
}

// GroupProperties holds the AD group attributes.
type GroupProperties struct {
	BaseProperties
	Name                   string   `json:"name"`
	SAMAccountName         string   `json:"samaccountname"` // Optional?
	IsACLProtected         bool     `json:"isaclprotected"`
	AdminCount             bool     `json:"admincount"` // Optional?
	HighValue              bool     `json:"highvalue"`
	SIDHistory             []string `json:"sidhistory"`
	AdminSDHolderProtected bool     `json:"adminsdholderprotected"`
}

type Computer struct {
	BaseADObject
	DomainSID               string                      `json:"DomainSID"`
	AllowedToAct            []TypedPrincipal            `json:"AllowedToAct"`
	AllowedToDelegate       []TypedPrincipal            `json:"AllowedToDelegate"`
	UnconstrainedDelegation bool                        `json:"UnconstrainedDelegation"`
	PrimaryGroupSID         string                      `json:"PrimaryGroupSID"`
	LocalGroups             []LocalGroupAPIResult       `json:"LocalGroups"`
	Sessions                SessionAPIResult            `json:"Sessions"`
	PrivilegedSessions      SessionAPIResult            `json:"PrivilegedSessions"`
	RegistrySessions        SessionAPIResult            `json:"RegistrySessions"`
	Properties              ComputerProperties          `json:"Properties"`
	HasSIDHistory           []TypedPrincipal            `json:"HasSIDHistory"`
	Status                  ComputerStatus              `json:"Status"` // TODO: Fill
	UserRights              []UserRightsAPIResult       `json:"UserRights"`
	DumpSMSAPassword        []TypedPrincipal            `json:"DumpSMSAPassword"`
	DCRegistryData          DCRegistryData              `json:"DCRegistryData"`
	NTLMRegistryData        NTLMRegistryData            `json:"NTLMRegistryData"`
	IsWebClientRunning      IsWebClientRunningAPIResult `json:"IsWebClientRunning"`
	IsDC                    bool                        `json:"IsDC"`
}

type ComputerProperties struct {
	BaseProperties
	Name                     string   `json:"name"`
	SAMAccountName           string   `json:"samaccountname"`
	HasLAPS                  bool     `json:"haslaps"`
	IsACLProtected           bool     `json:"isaclprotected"`
	AdminSDHolderProtected   bool     `json:"adminsdholderprotected"`
	Enabled                  bool     `json:"enabled"`
	UnconstrainedDelegation  bool     `json:"unconstraineddelegation"`
	TrustedToAuth            bool     `json:"trustedtoauth"`
	IsDC                     bool     `json:"isdc"`
	IsReadOnlyDC             bool     `json:"isreadonlydc"`
	EncryptedTextPwdAllowed  bool     `json:"encryptedtextpwdallowed"`
	UseDesKeyOnly            bool     `json:"usedeskeyonly"`
	LogonScriptEnabled       bool     `json:"logonscriptenabled"`
	LockedOut                bool     `json:"lockedout"`
	PasswordExpired          bool     `json:"passwordexpired"`
	SupportedEncryptionTypes []string `json:"supportedencryptiontypes"`
	AdminCount               bool     `json:"admincount"`
	LastLogon                int64    `json:"lastlogon"`
	LastLogonTimestamp       int64    `json:"lastlogontimestamp"`
	PwdLastSet               int64    `json:"pwdlastset"`
	ServicePrincipalNames    []string `json:"serviceprincipalnames"`
	Email                    string   `json:"email"`
	UserAccountControl       int64    `json:"useraccountcontrol"`
	OperatingSystem          string   `json:"operatingsystem"`
	SIDHistory               []string `json:"sidhistory"`
	ObjectGUID               string   `json:"objectguid"`
	AllowedToDelegate        []string `json:"allowedtodelegate,omitempty"`
	LdapAvailable            *bool    `json:"ldapavailable,omitempty"`
	LdapsAvailable           *bool    `json:"ldapsavailable,omitempty"`
	LdapSigning              *bool    `json:"ldapsigning,omitempty"`
	LdapsEpa                 *bool    `json:"ldapsepa,omitempty"`
}

type ComputerStatus struct {
	Connectable bool   `json:"Connectable"`
	Error       string `json:"Error"`
}

type WellKnownGroup struct {
	BaseADObject
	Properties WellKnownProperties `json:"Properties"`
	Members    []TypedPrincipal    `json:"Members"`
}

type WellKnownUser struct {
	BaseADObject
	Properties WellKnownProperties `json:"Properties"`
}

type WellKnownProperties struct {
	BaseProperties
	Name string `json:"name"`
}

// General types
type TypedPrincipal struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

type NamedPrincipal struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	PrincipalName    string `json:"PrincipalName"`
}

// Active collection types
type APIResult struct {
	Collected     bool    `json:"Collected"`
	FailureReason *string `json:"FailureReason"`
}

type Session struct {
	ComputerSID string `json:"ComputerSID"`
	UserSID     string `json:"UserSID"`
}

type SessionAPIResult struct {
	APIResult
	Results []Session `json:"Results"`
}

type LocalGroupAPIResult struct {
	APIResult
	ObjectIdentifier string           `json:"ObjectIdentifier"`
	Name             string           `json:"Name"`
	Results          []TypedPrincipal `json:"Results"`
	LocalNames       []NamedPrincipal `json:"LocalNames"`
}

// Registry-related types
type RegistryAPIResult struct {
	APIResult
	Value []byte
}

type IntRegistryAPIResult struct {
	APIResult
	Value int
}

type BoolRegistryAPIResult struct {
	APIResult
	Value bool
}

type StrRegistryAPIResult struct {
	APIResult
	Value string
}

type UserRightsAPIResult struct {
	APIResult
	Privilege  string
	Results    []TypedPrincipal
	LocalNames []NamedPrincipal
}

type UserRightsAssignmentAPIResult struct {
	APIResult
	Privilege  string
	Results    []TypedPrincipal
	LocalNames []NamedPrincipal
}

type IsWebClientRunningAPIResult struct {
	APIResult
	Result *bool
}

type IsChannelBindingRequiredAPIResult struct {
	APIResult
	Result *bool
}

type IsSigningRequiredAPIResult struct {
	APIResult
	Result *bool
}

type LdapServicesResult struct {
	HasLdap                  bool                              `json:"HasLdap"`
	HasLdaps                 bool                              `json:"HasLdaps"`
	IsSigningRequired        IsSigningRequiredAPIResult        `json:"IsSigningRequired"`
	IsChannelBindingRequired IsChannelBindingRequiredAPIResult `json:"IsChannelBindingRequired"`
}

type NTLMSessionAPIResult struct {
	APIResult
	Sessions           []NTLMSession
	CollectionDuration time.Duration
}

type NTLMSession struct {
	TimeCreatedUtc string `json:"TimeCreatedUtc"`
	Id             string `json:"Id"`
	AccountSid     string `json:"AccountSid"`
	AccountName    string `json:"AccountName"`
	AccountDomain  string `json:"AccountDomain"`
	SourceHost     string `json:"SourceHost"`
	SourceIp       string `json:"SourceIp"`
	SourcePort     string `json:"SourcePort"`
	PackageName    string `json:"PackageName"`
}

type NTLMRegistryValues struct {
	RestrictSendingNtlmTraffic   *uint32  `json:"RestrictSendingNtlmTraffic"`
	RestrictReceivingNtlmTraffic *uint32  `json:"RestrictReceivingNtlmTraffic"`
	NtlmMinServerSec             *uint32  `json:"NtlmMinServerSec"`
	NtlmMinClientSec             *uint32  `json:"NtlmMinClientSec"`
	LmCompatibilityLevel         *uint32  `json:"LmCompatibilityLevel"`
	UseMachineId                 *uint32  `json:"UseMachineId"`
	RequireSecuritySignature     *uint32  `json:"RequireSecuritySignature"`
	EnableSecuritySignature      *uint32  `json:"EnableSecuritySignature"`
	ClientAllowedNTLMServers     []string `json:"ClientAllowedNTLMServers"`
}

type NTLMRegistryData struct {
	APIResult
	Result NTLMRegistryValues
}

type SMBInfoAPIResult struct {
	APIResult
	Result map[string]string
}

type DCRegistryData struct {
	CertificateMappingMethods            *IntRegistryAPIResult
	StrongCertificateBindingEnforcement  *IntRegistryAPIResult
	VulnerableNetlogonSecurityDescriptor *StrRegistryAPIResult
}

// CAEnrollmentEndpointType represents the type of enrollment endpoint
type CAEnrollmentEndpointType int

const (
	// The Certificate Authority Web Enrollment server role, an ASP web application
	CATypeWebEnrollmentApplication CAEnrollmentEndpointType = iota
	// The Certificate Enrollment Web Service (CES) server role, a SOAP-based web service
	CATypeEnrollmentWebService
	// The Network Device Enrollment Service (NDES), which uses the SCEP protocol to obtain certificates.
	CATypeEnrollmentNDES
	// ICertPassage Remote Protocol (MS-ICPR), an RPC protcol
	CATypeEnrollmentRPC
	// The Windows Client Certificate Enrollment Protocol (MS-WCCE), a set of DCOM interfaces for certificate enrollment
	CATypeEnrollmentDCOM
)

// CAEnrollmentEndpointScanResult represents the scan result status
type CAEnrollmentEndpointScanResult int

const (
	// Endpoint is vulnerable due to using HTTP (not HTTPS) with NTLM auth (ESC8)
	CAScanVulnerableNtlmHttpEndpoint CAEnrollmentEndpointScanResult = iota
	// Endpoint is vulnerable due to using HTTP (not HTTPS) with Kerberos auth
	CAScanVulnerableKerberosHttpEndpoint
	// Endpoint is vulnerable due to not requiring channel binding for the HTTPS endpoint (ESC8)
	CAScanVulnerableNtlmHttpsNoChannelBinding
	// Endpoint is not vulnerable due to not existing
	CAScanNotVulnerablePortInaccessible
	// The server did not return an NTLM challenge (e.g., when Negotiate:Kerberos is enabled)
	CAScanNotVulnerableNoNtlmChallenge
	// 404 NotFound when accessing the endpoint
	CAScanNotVulnerablePathNotFound
	// Returned if the IIS is configured to require SSL (so no HTTP possible)
	CAScanNotVulnerablePathForbidden
	// 500 Server Error when visiting URL and error reveals ExtendedProtectionPolicy is misconfigured.
	// Occurs when IIS's EPA settings differ from site's web.config's ExtendedProtectionPolicy setting.
	CAScanNotVulnerableEpaMisconfigured
	// Endpoint is not vulnerable due requiring ChannelBinding or only supporting Kerberos authentication (or both)
	CAScanNotVulnerableNtlmChannelBindingRequired
	// ?
	CAScanError
)

type CAEnrollmentEndpoint struct {
	Url                    string                         `json:"Url"`
	Type                   CAEnrollmentEndpointType       `json:"CAEnrollmentEndpointType"`
	Status                 CAEnrollmentEndpointScanResult `json:"CAEnrollmentEndpointScanResult"`
	ADCSWebEnrollmentHTTP  bool                           `json:"ADCSWebEnrollmentHTTP"`
	ADCSWebEnrollmentHTTPS bool                           `json:"ADCSWebEnrollmentHTTPS"`
	ADCSWebEnrollmentEPA   bool                           `json:"ADCSWebEnrollmentEPA"`
}

type CAEnrollmentEndpointAPIResult struct {
	APIResult
	Result CAEnrollmentEndpoint `json:"Result"`
}

type AceRegistryAPIResult struct {
	APIResult
	Data []ACE `json:"Data"`
}

type EnrollmentAgentRestriction struct {
	AccessType   string           `json:"AccessType"`
	Agent        TypedPrincipal   `json:"Agent"`
	Targets      []TypedPrincipal `json:"Targets"`
	Template     *TypedPrincipal  `json:"Template"`
	AllTemplates bool             `json:"AllTemplates"`
}

type EnrollmentAgentRegistryAPIResult struct {
	APIResult
	Restrictions []EnrollmentAgentRestriction `json:"Restrictions"`
}

type CARegistryData struct {
	CASecurity                  AceRegistryAPIResult             `json:"CASecurity"`
	EnrollmentAgentRestrictions EnrollmentAgentRegistryAPIResult `json:"EnrollmentAgentRestrictions"`
	IsUserSpecifiesSanEnabled   BoolRegistryAPIResult            `json:"IsUserSpecifiesSanEnabled"`
	IsRoleSeparationEnabled     BoolRegistryAPIResult            `json:"IsRoleSeparationEnabled"`
}

type AIACA struct {
	BaseADObject
	Properties AIACAProperties `json:"Properties"`
}

type AIACAProperties struct {
	BaseProperties
	Name                      string   `json:"name"`
	CrossCertificatePair      []byte   `json:"crosscertificatepair"`
	HasCrossCertificatePair   bool     `json:"hascrosscertificatepair"`
	CertThumbprint            string   `json:"certthumbprint"`
	CertName                  string   `json:"certname"`
	CertChain                 []string `json:"certchain"`
	HasBasicConstraints       bool     `json:"hasbasicconstraints"`
	BasicConstraintPathLength int      `json:"basicconstraintpathlength"`
}

type NTAuthStore struct {
	BaseADObject
	DomainSID  string                `json:"DomainSID"`
	Properties NTAuthStoreProperties `json:"Properties"`
}

type NTAuthStoreProperties struct {
	BaseProperties
	Name            string   `json:"name"`
	CertThumbprints []string `json:"certthumbprints"`
}

type EnterpriseCAProperties struct {
	BaseProperties
	Name                                 string   `json:"name"`
	CAName                               string   `json:"caname"`
	DNSHostname                          string   `json:"dnshostname"`
	Flags                                string   `json:"flags"`
	CertThumbprint                       string   `json:"certthumbprint"`
	CertName                             string   `json:"certname"`
	CertChain                            []string `json:"certchain"`
	HasBasicConstraints                  bool     `json:"hasbasicconstraints"`
	BasicConstraintPathLength            int      `json:"basicconstraintpathlength"`
	CASecurityCollected                  bool     `json:"casecuritycollected"`
	EnrollmentAgentRestrictionsCollected bool     `json:"enrollmentagentrestrictionscollected"`
	IsUserSpecifiesSanEnabledCollected   bool     `json:"isuserspecifiessanenabledcollected"`
	RoleSeparationEnabledCollected       bool     `json:"roleseparationenabledcollected"`
	UnresolvedPublishedTemplates         []string `json:"unresolvedpublishedtemplates"`
}

type EnterpriseCA struct {
	BaseADObject
	Properties              EnterpriseCAProperties          `json:"Properties"`
	HostingComputer         string                          `json:"HostingComputer"`
	CARegistryData          CARegistryData                  `json:"CARegistryData"`
	EnabledCertTemplates    []TypedPrincipal                `json:"EnabledCertTemplates"`
	HttpEnrollmentEndpoints []CAEnrollmentEndpointAPIResult `json:"HttpEnrollmentEndpoints"`
}

type CertTemplate struct {
	BaseADObject
	Properties CertTemplateProperties `json:"Properties"`
}

type CertTemplateProperties struct {
	BaseProperties
	Name                          string   `json:"name"`
	ValidityPeriod                string   `json:"validityperiod"`
	RenewalPeriod                 string   `json:"renewalperiod"`
	SchemaVersion                 uint32   `json:"schemaversion"`
	DisplayName                   string   `json:"displayname"`
	OID                           string   `json:"oid"`
	EnrollmentFlag                string   `json:"enrollmentflag"`
	RequiresManagerApproval       bool     `json:"requiresmanagerapproval"`
	NoSecurityExtension           bool     `json:"nosecurityextension"`
	CertificateNameFlag           string   `json:"certificatenameflag"`
	EnrolleeSuppliesSubject       bool     `json:"enrolleesuppliessubject"`
	SubjectAltRequireUPN          bool     `json:"subjectaltrequireupn"`
	SubjectAltRequireDNS          bool     `json:"subjectaltrequiredns"`
	SubjectAltRequireDomainDNS    bool     `json:"subjectaltrequiredomaindns"`
	SubjectAltRequireEmail        bool     `json:"subjectaltrequireemail"`
	SubjectAltRequireSPN          bool     `json:"subjectaltrequirespn"`
	SubjectRequireEmail           bool     `json:"subjectrequireemail"`
	EKUs                          []string `json:"ekus"`
	CertificateApplicationPolicy  []string `json:"certificateapplicationpolicy"`
	CertificatePolicy             []string `json:"certificatepolicy"`
	AuthorizedSignatures          int64    `json:"authorizedsignatures"`
	ApplicationPolicies           []string `json:"applicationpolicies"`
	IssuancePolicies              []string `json:"issuancepolicies"`
	EffectiveEKUs                 []string `json:"effectiveekus"`
	AuthenticationEnabled         bool     `json:"authenticationenabled"`
	SchannelAuthenticationEnabled bool     `json:"schannelauthenticationenabled"`
}

type IssuancePolicy struct {
	BaseADObject
	Properties IssuancePolicyProperties `json:"Properties"`
	GroupLink  TypedPrincipal           `json:"GroupLink"`
}

type IssuancePolicyProperties struct {
	BaseProperties
	Name            string `json:"name"`
	DisplayName     string `json:"displayname"`
	CertTemplateOID string `json:"certtemplateoid"`
	OIDGroupLink    string `json:"oidgrouplink,omitempty"`
}

type RootCA struct {
	BaseADObject
	DomainSID  string           `json:"DomainSID"`
	Properties RootCAProperties `json:"Properties"`
}

type RootCAProperties struct {
	BaseProperties
	Name                      string   `json:"name"`
	CertThumbprint            string   `json:"certthumbprint"`
	CertName                  string   `json:"certname"`
	CertChain                 []string `json:"certchain"`
	HasBasicConstraints       bool     `json:"hasbasicconstraints"`
	BasicConstraintPathLength int      `json:"basicconstraintpathlength"`
}

// TODO: Improve usage of these labels
type ObjectTypeEnum uint8

const (
	BaseObjectType ObjectTypeEnum = iota
	UserObjectType
	ComputerObjectType
	GroupObjectType
	LocalGroupObjectType
	LocalUserObjectType
	GPOObjectType
	DomainObjectType
	OUObjectType
	ContainerObjectType
	ConfigurationObjectType
	CertTemplateObjectType
	RootCAObjectType
	AIACAObjectType
	EnterpriseCAObjectType
	NTAuthStoreObjectType
	IssuancePolicyObjectType
	FSPObjectType
	TrustAccountObjectType
)

var ObjectTypeRawToStrMap = map[ObjectTypeEnum]string{
	BaseObjectType:           "Base",
	UserObjectType:           "User",
	ComputerObjectType:       "Computer",
	GroupObjectType:          "Group",
	LocalGroupObjectType:     "LocalGroup",
	LocalUserObjectType:      "LocalUser",
	GPOObjectType:            "GPO",
	DomainObjectType:         "Domain",
	OUObjectType:             "OU",
	ContainerObjectType:      "Container",
	ConfigurationObjectType:  "Configuration",
	CertTemplateObjectType:   "CertTemplate",
	RootCAObjectType:         "RootCA",
	AIACAObjectType:          "AIACA",
	EnterpriseCAObjectType:   "EnterpriseCA",
	NTAuthStoreObjectType:    "NTAuthStore",
	IssuancePolicyObjectType: "IssuancePolicy",
	FSPObjectType:            "foreignsecurityprincipal",
	TrustAccountObjectType:   "trustaccount",
}

var StrToObjectTypeRawMap = map[string]ObjectTypeEnum{
	"Base":                     BaseObjectType,
	"User":                     UserObjectType,
	"Computer":                 ComputerObjectType,
	"Group":                    GroupObjectType,
	"LocalGroup":               LocalGroupObjectType,
	"LocalUser":                LocalUserObjectType,
	"GPO":                      GPOObjectType,
	"Domain":                   DomainObjectType,
	"OU":                       OUObjectType,
	"Container":                ContainerObjectType,
	"Configuration":            ConfigurationObjectType,
	"CertTemplate":             CertTemplateObjectType,
	"RootCA":                   RootCAObjectType,
	"AIACA":                    AIACAObjectType,
	"EnterpriseCA":             EnterpriseCAObjectType,
	"NTAuthStore":              NTAuthStoreObjectType,
	"IssuancePolicy":           IssuancePolicyObjectType,
	"foreignsecurityprincipal": FSPObjectType,
	"trustaccount":             TrustAccountObjectType,
}
