package builder

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Macmod/flashingestor/config"
	gildap "github.com/Macmod/flashingestor/ldap"
	"github.com/Macmod/flashingestor/msrpc"
	"github.com/cespare/xxhash/v2"
)

// GetHash computes a 64-bit hash of the upper-case string.
func GetHash(s string) uint64 {
	return xxhash.Sum64String(strings.ToUpper(s))
}

// ResolveSIDFromCache looks up a SID in the cache and returns the typed principal.
func ResolveSIDFromCache(sid string) (TypedPrincipal, bool) {
	var out TypedPrincipal
	cachedEntry, ok := BState().SIDCache.Get(sid)
	if ok {
		out = cachedEntry.ToTypedPrincipal()
		return out, true
	}
	return out, false
}

// ResolveSID resolves a SID to a typed principal, checking well-known SIDs first.
func ResolveSID(sid string, domainName string) TypedPrincipal {
	var out TypedPrincipal
	if wks, ok := BState().WellKnown.Get(sid); ok {
		out.ObjectIdentifier = fmt.Sprintf("%s-%s", strings.ToUpper(domainName), sid)
		out.ObjectType = capitalize(wks.Type)
	} else {
		cachedEntry, ok := ResolveSIDFromCache(sid)
		if ok {
			out = cachedEntry
		} else {
			// TODO: If it's not in the current domain... try to find it somewhere?
			out.ObjectIdentifier = sid
			out.ObjectType = "Base"
		}
	}

	return out
}

func ResolveADEntry(entry gildap.LDAPEntry) map[string]string {
	resolved := make(map[string]string)

	account := entry.GetAttrVal("sAMAccountName", "")
	dn := entry.DN

	var domain string
	if dn != "" {
		domain = entry.GetDomainFromDN()
	}

	objectClass := entry.GetAttrVals("objectClass", []string{})
	resolved["objectid"] = entry.GetSID()
	resolved["principal"] = strings.ToUpper(account + "@" + domain)

	if account == "" {
		// If there is no sAMAccountName, try to get some
		// sort of identifier to replace the principal
		// and figure out the type
		if slices.Contains(objectClass, "domain") {
			resolved["type"] = "Domain"
			/*
				} else if strings.Contains(dn, "ForeignSecurityPrincipals") && !slices.Contains(objectClass, "container") {
					// Handle foreign security principals
					resolved["principal"] = strings.ToUpper(domain)
					resolved["type"] = "foreignsecurityprincipal"
					ename := entry.GetAttrVal("name", "")
					if ename != "" {
						if wk, ok := BState().WellKnown.Get(ename); ok {
							name, sidtype := wk.Name, wk.Type
							resolved["type"] = capitalize(sidtype)
							resolved["principal"] = strings.ToUpper(name + "@" + domain)
							resolved["objectid"] = strings.ToUpper(domain) + "-" + resolved["objectid"]
						} else {
							resolved["objectid"] = ename
						}
					}
			*/
		} else if guidStr := entry.GetGUID(); guidStr != "" {
			// Handle objects with GUIDs (OUs / Containers, etc)
			resolved["objectid"] = strings.ToUpper(guidStr)
			name := entry.GetAttrVal("name", "")
			resolved["principal"] = strings.ToUpper(name + "@" + domain)

			if slices.Contains(objectClass, "organizationalUnit") {
				resolved["type"] = "OU"
			} else if slices.Contains(objectClass, "container") {
				resolved["type"] = "Container"
			} else {
				resolved["type"] = "Base"
			}
		} else {
			resolved["type"] = "Base"
		}
	} else {
		// If there is a sAMAccountName, it's a nice principal; just fill its type field
		accountTypeVal := entry.GetAttrVal("sAMAccountType", "")
		accountType, _ := strconv.Atoi(accountTypeVal)

		switch {
		case slices.Contains([]int{268435456, 268435457, 536870912, 536870913}, accountType):
			resolved["type"] = "Group"
		case accountType == 805306368 ||
			slices.Contains(objectClass, "msDS-GroupManagedServiceAccount") ||
			slices.Contains(objectClass, "msDS-ManagedServiceAccount"):
			resolved["type"] = "User"
		case accountType == 805306369:
			resolved["type"] = "Computer"
			shortName := strings.TrimSuffix(account, "$")
			resolved["principal"] = strings.ToUpper(shortName + "." + domain)
		case accountType == 805306370:
			resolved["type"] = "trustaccount"
		default:
			resolved["type"] = "Base"
		}
	}

	return resolved
}

/*
	func ResolveTarget(target string, domain string) TypedPrincipal {
		targetSlice := strings.Split(target, "/")
		targetAddr := targetSlice[1]
		targetAddrSlice := strings.Split(targetAddr, ":")
		targetHost := targetAddrSlice[0]

		if entry, exists := BState().HostDnsCache.Get(domain + "+" + targetHost); exists {
			resolvedObj := entry.ToTypedPrincipal()
			return resolvedObj
		}

		targetHostSamPrefix := strings.Split(targetHost, ".")[0]

		// Try the prefix without $
		if entry, exists := BState().SamCache.Get(domain + "+" + targetHostSamPrefix); exists {
			resolvedObj := entry.ToTypedPrincipal()
			return resolvedObj
		}

		// Try the prefix with $
		if entry, exists := BState().SamCache.Get(domain + "+" + targetHostSamPrefix + "$"); exists {
			resolvedObj := entry.ToTypedPrincipal()
			return resolvedObj
		}

		// TODO:
		// 1) Cache SamNames via GC

		return TypedPrincipal{
			ObjectIdentifier: targetHost,
			ObjectType:       "Base",
		}
	}
*/

func ResolveGroupName(baseName string, computerName string, computerDomainSid string, domainName string, groupRid int, isDC bool, isBuiltin bool) *NamedPrincipal {
	if isDC {
		if isBuiltin {
			// Builtin domain groups on a DC
			groupSid := "S-1-5-32-" + fmt.Sprint(groupRid)
			wksDesc, ok := BState().WellKnown.Get(groupSid)
			if ok {
				return &NamedPrincipal{
					ObjectIdentifier: groupSid,
					PrincipalName:    wksDesc.Name,
				}
			}
		}

		if computerDomainSid == "" {
			return nil
		}

		return &NamedPrincipal{
			ObjectIdentifier: computerDomainSid + "-" + fmt.Sprint(groupRid),
			PrincipalName:    "IGNOREME",
		}
	}

	return &NamedPrincipal{
		ObjectIdentifier: fmt.Sprintf("%s-%s", computerDomainSid, fmt.Sprint(groupRid)),
		PrincipalName:    strings.ToUpper(baseName + "@" + computerName),
	}
}

func IsFilteredContainer(containerDN string) bool {
	if containerDN == "" {
		return true
	}

	dn := strings.ToUpper(containerDN)
	if strings.Contains(dn, "CN=DOMAINUPDATES,CN=SYSTEM,DC=") {
		return true
	}
	if strings.Contains(dn, "CN=POLICIES,CN=SYSTEM,DC=") &&
		(strings.HasPrefix(dn, "CN=USER") || strings.HasPrefix(dn, "CN=MACHINE")) {
		return true
	}
	return false
}

// IsFilteredContainerChild replicates the Python is_filtered_container_child function.
// It checks if a child container DN should be ignored.
/*
func IsFilteredContainerChild(containerDN string) bool {
	if containerDN == "" {
		return false
	}
	dn := strings.ToUpper(containerDN)
	if strings.Contains(dn, "CN=PROGRAM DATA,DC=") {
		return true
	}
	if strings.Contains(dn, "CN=SYSTEM,DC=") {
		return true
	}
	return false
}
*/

// ParseGPLinkString parses a GPLink string according to MS-GPOL:
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/08090b22-bc16-49f4-8e10-f27a8fb16d18
// The return value is a slice of (DN, Option) pairs.

type GPLinkRef struct {
	GUID       string
	IsEnforced bool
}

type GPLink struct {
	DN     string
	Option int
}

func ParseGPLinkString(linkStr string) []GPLink {
	if linkStr == "" {
		return nil
	}

	var results []GPLink
	parts := strings.Split(linkStr, "LDAP://")
	for _, part := range parts[1:] {
		// Each part looks like: "CN=...,DC=...;0][CN=..."
		cleaned := strings.TrimRight(part, "][ ")
		split := strings.SplitN(cleaned, ";", 2)
		if len(split) != 2 {
			continue
		}
		dn := split[0]
		opt, err := strconv.Atoi(split[1])
		if err != nil {
			continue
		}
		results = append(results, GPLink{DN: dn, Option: opt})
	}
	return results
}

// Converts time in format 20060102150405.0Z into Unix epoch seconds.
func FormatTime1(whenCreatedStr string) int64 {
	var whenCreatedEpoch int64
	if whenCreatedStr != "" {
		t, err := time.Parse("20060102150405.0Z", whenCreatedStr)
		if err == nil {
			whenCreatedEpoch = t.Unix()
		}
	}

	return whenCreatedEpoch
}

// Converts a Windows FILETIME to Unix epoch seconds.
func FormatTime2(fileTimeStr string) int64 {
	if fileTimeStr == "" {
		return 0
	}

	// Active Directory timestamps are in 100-nanosecond intervals since Jan 1, 1601.
	var ft int64
	_, err := fmt.Sscan(fileTimeStr, &ft)
	if err != nil || ft == 0 {
		return 0
	}
	// Convert: subtract epoch difference and divide by 10,000,000 to get seconds.
	unixTime := (ft / 10000000) - 11644473600
	return unixTime
}

func capitalize(s string) string {
	if s == "" {
		return ""
	}

	r, size := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + strings.ToLower(s[size:])
}

// CertificateInfo holds parsed certificate information
type CertificateInfo struct {
	Thumbprint                string
	Name                      string
	Chain                     []string
	HasBasicConstraints       bool
	BasicConstraintPathLength int
}

// ParseCACertificate parses a cACertificate attribute and returns certificate information
func ParseCACertificate(certData []byte) *CertificateInfo {
	if certData == nil || len(certData) == 0 {
		return nil
	}

	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil
	}

	// Thumbprint (SHA-1)
	hash := sha1.Sum(cert.Raw)
	thumbprint := strings.ToUpper(hex.EncodeToString(hash[:]))

	// Certificate Name always falls back to thumbprint (not sure how to parse FriendlyName for now)
	name := thumbprint

	// Certificate Chain - build the full chain including the certificate itself
	certChain := []string{thumbprint}

	// Basic Constraints
	hasBasicConstraints := false
	basicConstraintPathLength := 0

	if cert.BasicConstraintsValid && cert.IsCA {
		// Path length constraint exists if MaxPathLenZero is true or MaxPathLen > 0
		hasBasicConstraints = cert.MaxPathLenZero || cert.MaxPathLen > 0
		if cert.MaxPathLen < 0 {
			basicConstraintPathLength = 0
		} else {
			basicConstraintPathLength = cert.MaxPathLen
		}
	}

	return &CertificateInfo{
		Thumbprint:                thumbprint,
		Name:                      name,
		Chain:                     certChain,
		HasBasicConstraints:       hasBasicConstraints,
		BasicConstraintPathLength: basicConstraintPathLength,
	}
}

func stripServicePrincipalName(host string) string {
	parts := strings.Split(host, "/")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	return host
}

// RequestNETBIOSNameFromComputer queries a computer's NetBIOS name via UDP port 137
// Returns the NetBIOS name and whether the query was successful
func RequestNETBIOSNameFromComputer(ctx context.Context, ipAddress string, timeout time.Duration) (string, bool) {
	// Create a context with timeout
	if timeout == 0 {
		timeout = 1 * time.Second
	}

	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// NetBIOS Name Request packet - matches SharpHound's NameRequest
	// This is a standard NBSTAT query for "*" (wildcard)
	packet := []byte{
		0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
		0x00, 0x01,
	}

	// Set up UDP connection
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(queryCtx, "udp", ipAddress+":137")
	if err != nil {
		return "", false
	}
	defer conn.Close()

	// Set deadline for the connection
	deadline, ok := queryCtx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}

	// Send the query
	_, err = conn.Write(packet)
	if err != nil {
		return "", false
	}

	// Read the response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return "", false
	}

	// Response must be at least 90 bytes (SharpHound compatibility check)
	// This ensures we have enough data to read the first NetBIOS name
	if n < 90 {
		return "", false
	}

	// Extract NetBIOS name from fixed offset 57 (16 bytes)
	// This matches SharpHound's approach - simpler and more reliable than full parsing
	// Offset 57 is where the first NetBIOS name entry starts in a standard NBSTAT response
	netbiosName := string(response[57:73])

	// Trim null bytes and spaces
	netbiosName = strings.Trim(netbiosName, "\x00 ")

	if netbiosName == "" {
		return "", false
	}

	return strings.ToUpper(netbiosName), true
}

func ResolveHostnameInCaches(host string, domain string) (string, bool) {
	// Check if we already have this host cached in HostDnsCache
	if entry, ok := BState().HostDnsCache.Get(domain + "+" + host); ok {
		return entry.ObjectIdentifier, true
	}

	split := strings.Split(host, ".")
	name := split[0]

	// Check the SamCache for HOST$ in the specified domain
	if entry, ok := BState().SamCache.Get(domain + "+" + name + "$"); ok {
		return entry.ObjectIdentifier, true
	}

	// Check the SamCache for HOST$ in the target domain extracted from FQDN
	if len(split) > 1 {
		tempDomain := strings.Join(split[1:], ".")
		if entry, ok := BState().SamCache.Get(tempDomain + "+" + name + "$"); ok {
			return entry.ObjectIdentifier, true
		}
	}

	return "", false
}

// ResolveSpn resolves a service principal name (SPN) to a computer SID using caches
// This is different from SharpHound's implementation of ResolveHostToSid in which
// they try to issue (1) NetrWkstaGetInfo, (2) reverse DNS (if the strippedHost is an IP) and (3) NetBIOS
// In our current implementation we only check our existing caches, which might lead to false negatives
// Also, SharpHound uses the same ResolveHostToSid to map SPNs in AllowedToDelegateTo / ServicePrincipalNames and
// for resolving the hosting computer of an Enterprise CA,
// whereas we split these two use cases into ResolveSpn and ResolveHostname respectively.
func ResolveSpn(host string, domain string) (string, bool) {
	// Remove SPN prefixes from the host name so we're working with a clean name
	strippedHost := strings.ToUpper(strings.TrimSuffix(stripServicePrincipalName(host), "$"))
	if strippedHost == "" {
		return "", false
	}

	return ResolveHostnameInCaches(strippedHost, domain)
}

func inferNetBIOSName(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 0 {
		firstPart := strings.ToUpper(parts[0])
		if len(firstPart) <= 15 {
			return firstPart
		}
		return firstPart[:15]
	}

	return ""
}

// ResolveHostname resolves a hostname to a computer SID using RPC queries, NetBIOS and caches
func ResolveHostname(ctx context.Context, auth *config.CredentialMgr, host string, domain string) (string, bool) {
	rpcObj, err := msrpc.NewWkssvcRPC(ctx, host, auth)
	if err == nil {
		defer rpcObj.Close()

		wkstaInfo, err := rpcObj.GetWkstaInfo(ctx)
		if err == nil {
			if wkstaInfo.LANGroup != "" {
				// Sometimes FQDN, sometimes NetBIOS?
				// Review this behavior later
				domain = wkstaInfo.LANGroup
			}
			return ResolveHostnameInCaches(wkstaInfo.ComputerName, domain)
		}
	}

	if netbiosName, ok := RequestNETBIOSNameFromComputer(ctx, host, config.NETBIOS_TIMEOUT); ok && netbiosName != "" {
		host = netbiosName
	}

	return ResolveHostnameInCaches(host, domain)
}

func GetMachineSID(ctx context.Context, auth *config.CredentialMgr, computerName string, computerObjectId string) (string, error) {
	if machineSid, ok := BState().MachineSIDCache.Get(computerObjectId); ok {
		return machineSid.ObjectIdentifier, nil
	}

	rpcObj, err := msrpc.NewSamrRPC(ctx, computerName, auth)
	if err != nil {
		return "", err
	}
	defer rpcObj.Close()

	machineSid, err := rpcObj.GetMachineSid(computerName)
	if err != nil {
		return "", err
	}

	BState().MachineSIDCache.Set(computerObjectId, &Entry{
		ObjectIdentifier: machineSid.String(),
		ObjectTypeRaw:    ComputerObjectType,
	})

	return machineSid.String(), nil
}
