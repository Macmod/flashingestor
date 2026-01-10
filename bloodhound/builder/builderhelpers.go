package builder

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cespare/xxhash/v2"
)

/* Resolution-related functions */

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
			out.ObjectIdentifier = sid
			out.ObjectType = "Base"
		}
	}

	return out
}

// ResolveHostnameInCaches attempts to resolve a hostname to a computer SID
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

/* String/parsing-related functions */

// getHash computes a 64-bit hash of the upper-case string.
func getHash(s string) uint64 {
	return xxhash.Sum64String(strings.ToUpper(s))
}

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

func parseGPLinkString(linkStr string) []GPLink {
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
func formatTime1(whenCreatedStr string) int64 {
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
func formatTime2(fileTimeStr string) int64 {
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

// parseCACertificate parses a cACertificate attribute and returns certificate information
func parseCACertificate(certData []byte) *CertificateInfo {
	if len(certData) == 0 {
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
