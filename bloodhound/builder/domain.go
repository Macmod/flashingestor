package builder

import (
	"encoding/hex"
	"strconv"
	"strings"

	gildap "github.com/Macmod/flashingestor/ldap"
)

var trustFlags = map[string]int{
	"NON_TRANSITIVE":                           0x00000001,
	"UPLEVEL_ONLY":                             0x00000002,
	"QUARANTINED_DOMAIN":                       0x00000004,
	"FOREST_TRANSITIVE":                        0x00000008,
	"CROSS_ORGANIZATION":                       0x00000010,
	"WITHIN_FOREST":                            0x00000020,
	"TREAT_AS_EXTERNAL":                        0x00000040,
	"USES_RC4_ENCRYPTION":                      0x00000080,
	"CROSS_ORGANIZATION_NO_TGT_DELEGATION":     0x00000200,
	"PIM_TRUST":                                0x00000400,
	"CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION": 0x00000800,
}

var bhTrustDirection = map[int]string{
	0x01: "Inbound",
	0x02: "Outbound",
	0x03: "Bidirectional",
}

// hasFlag checks if a specific trust flag is set
func hasFlag(flags int, flag string) bool {
	flagValue, exists := trustFlags[flag]
	if !exists {
		return false
	}
	return flags&flagValue == flagValue
}

func parseTrust(flags int, direction int) (string, string, bool, bool, bool) {
	// Reference logic extracted from SharpHoundCommon
	// instead of Bloodhoundpy to ensure consistency
	trustTypeStr := "Unknown"
	if hasFlag(flags, "WITHIN_FOREST") {
		// Sometimes it's TreeRoot, but it shouldn't matter,
		// as SharpHound itself doesn't distinguish between them.
		// To dinstinguish them we would need to check the domain names.
		trustTypeStr = "ParentChild"
	} else if hasFlag(flags, "FOREST_TRANSITIVE") {
		trustTypeStr = "Forest"
	} else if !hasFlag(flags, "FOREST_TRANSITIVE") && !hasFlag(flags, "WITHIN_FOREST") {
		trustTypeStr = "External"
	}

	sidFiltering := hasFlag(flags, "QUARANTINED_DOMAIN") ||
		(!hasFlag(flags, "TREAT_AS_EXTERNAL") &&
			hasFlag(flags, "FOREST_TRANSITIVE"))

	isTransitive := !hasFlag(flags, "NON_TRANSITIVE")

	trustDirectionStr, ok := bhTrustDirection[direction]
	if !ok {
		trustDirectionStr = "Unknown"
	}

	tgtDelegation := !hasFlag(flags, "QUARANTINED_DOMAIN") &&
		(hasFlag(flags, "WITHIN_FOREST") ||
			hasFlag(flags, "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION"))
	return trustDirectionStr, trustTypeStr, isTransitive, sidFiltering, tgtDelegation
}

// BuildDomainFromEntry constructs a Domain object from LDAP entries.
func BuildDomainFromEntry(domainEntry *gildap.LDAPEntry, trustEntries []gildap.LDAPEntry) *Domain {
	if domainEntry == nil {
		return nil
	}

	// --- Functional level ---
	levelID := domainEntry.GetAttrVal("msDS-Behavior-Version", "")
	functionalLevel, ok := gildap.FUNCTIONAL_LEVELS[levelID]
	if !ok {
		return nil
	}

	// --- When created ---
	whenCreatedStr := domainEntry.GetAttrVal("whenCreated", "")
	whenCreated := gildap.FormatTime1(whenCreatedStr)

	// Domain name and SID
	domainName := domainEntry.GetDomainFromDN()
	domainSID := domainEntry.GetSID()

	var baseObj BaseADObject
	baseObj.FromEntry(domainEntry, "domain")

	// --- Core domain struct ---
	domain := &Domain{
		BaseADObject: baseObj,
		Properties: DomainProperties{
			BaseProperties: BaseProperties{
				Domain:            strings.ToUpper(domainName),
				DistinguishedName: strings.ToUpper(domainEntry.DN),
				DomainSID:         domainSID,
				WhenCreated:       whenCreated,
				Description:       domainEntry.GetAttrVal("description", ""),
			},
			Name:            strings.ToUpper(domainName),
			FunctionalLevel: functionalLevel,
			HighValue:       true,
			IsACLProtected:  false,
			Collected:       true,
		},
		Trusts:       []DomainTrust{},
		Links:        []GPLinkRef{},
		ChildObjects: []TypedPrincipal{},
		GPOChanges: GPOChanges{
			AffectedComputers:  []TypedPrincipal{},
			DcomUsers:          []TypedPrincipal{},
			LocalAdmins:        []TypedPrincipal{},
			PSRemoteUsers:      []TypedPrincipal{},
			RemoteDesktopUsers: []TypedPrincipal{},
		},
	}

	domain.Properties.BaseProperties.SetOwnerRightsFlags(baseObj.Aces)

	domain.Properties.IsACLProtected = domain.IsACLProtected

	// --- Collect: Trusts ---
	for _, trustEntry := range trustEntries {
		trustAttributesStr := trustEntry.GetAttrVal("trustAttributes", "0")
		trustAttributes := 0
		if trustAttributesStr != "" {
			if val, err := strconv.Atoi(trustAttributesStr); err == nil {
				trustAttributes = val
			}
		}

		// Parse trust direction
		trustDirectionStr := trustEntry.GetAttrVal("trustDirection", "0")
		trustDirection := 0
		if val, err := strconv.Atoi(trustDirectionStr); err == nil {
			trustDirection = val
		}

		trustDirectionStr, trustTypeStr, isTransitive, sidFiltering, tgtDelegation := parseTrust(trustAttributes, trustDirection)

		trustSidBytes := trustEntry.GetAttrRawVal("securityIdentifier", []byte{})

		trustSid := gildap.ConvertSID(hex.EncodeToString(trustSidBytes))

		trust := DomainTrust{
			Name:                 strings.ToUpper(trustEntry.GetAttrVal("name", "")),
			TrustDirection:       trustDirectionStr,
			TrustType:            trustTypeStr,
			SecurityID:           trustSid,
			SidFilteringEnabled:  sidFiltering,
			IsTransitive:         isTransitive,
			TGTDelegationEnabled: tgtDelegation,
		}

		domain.Trusts = append(domain.Trusts, trust)
	}

	// --- Collect: Child Entries ---
	childEntries, ok := BState().ChildCache.GetChildren(domainEntry.DN)
	if ok {
		for _, child := range childEntries {
			domain.ChildObjects = append(domain.ChildObjects, child.ToTypedPrincipal())
		}
	}

	// --- Parse linked GPOs ---
	gplinkStr := domainEntry.GetAttrVal("gPLink", "")
	gplinks := parseGPLinkString(gplinkStr)

	for _, link := range gplinks {
		if link.Option == 0 || link.Option == 2 {
			domainLink := GPLinkRef{
				IsEnforced: link.Option == 2,
			}

			entry, ok := BState().MemberCache.Get(link.DN)

			// TODO: Review second condition
			if ok && entry.ObjectIdentifier != "" {
				domainLink.GUID = entry.ObjectIdentifier
				domain.Links = append(domain.Links, domainLink)
			}
		}
	}

	return domain
}
