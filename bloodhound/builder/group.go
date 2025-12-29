package builder

import (
	"slices"
	"strings"

	gildap "github.com/Macmod/flashingestor/ldap"
)

func getMembership(dn string) (TypedPrincipal, bool) {
	if strings.Contains(dn, "CN=ForeignSecurityPrincipals,DC=") {
		foreignSidPart := strings.Split(dn, ",")[0]
		foreignSid := foreignSidPart[3:]
		e, ok := BState().SIDCache.Get(foreignSid)
		if !ok {
			return TypedPrincipal{
				ObjectIdentifier: foreignSid,
				ObjectType:       "Base", // Could not resolve SID, so mark as Base
			}, false
		}

		return e.ToTypedPrincipal(), true
	}

	e, ok := BState().MemberCache.Get(dn)
	if !ok {
		return TypedPrincipal{}, false
	}

	return e.ToTypedPrincipal(), true
}

func isHighValue(sid string) bool {
	highvalue := []string{"S-1-5-32-544", "S-1-5-32-550", "S-1-5-32-549", "S-1-5-32-551", "S-1-5-32-548"}

	if strings.HasSuffix(sid, "-512") || strings.HasSuffix(sid, "-516") || strings.HasSuffix(sid, "-519") {
		return true
	}

	if slices.Contains(highvalue, sid) {
		return true
	}
	return false
}

// BuildGroupFromEntry constructs a Group object from an LDAP entry.
func BuildGroupFromEntry(entry *gildap.LDAPEntry) (*Group, bool) {
	var baseObj BaseADObject
	baseObj.FromEntry(entry, "group")

	var baseProps BaseProperties
	baseProps.FromEntry(entry)
	baseProps.SetOwnerRightsFlags(baseObj.Aces)

	samAccountName := entry.GetAttrVal("sAMAccountName", "")
	groupName := strings.ToUpper(samAccountName) + "@" + baseProps.Domain

	sid := entry.GetSID()

	// Check AdminSDHolder protection
	adminSDHolderProtected := false
	securityDescriptor := entry.GetAttrRawVal("nTSecurityDescriptor", []byte{})
	if adminHash, ok := BState().AdminSDHolderHashCache[baseProps.Domain]; ok && len(securityDescriptor) > 0 {
		isProtected, err := IsAdminSDHolderProtected(securityDescriptor, adminHash, groupName)
		if err == nil {
			adminSDHolderProtected = isProtected
		}
	}

	group := &Group{
		BaseADObject: baseObj,
		Properties: GroupProperties{
			BaseProperties:         baseProps,
			SIDHistory:             entry.GetAttrVals("sIDHistory", []string{}),
			Name:                   groupName,
			HighValue:              isHighValue(sid),
			AdminSDHolderProtected: adminSDHolderProtected,
		},
		Members: []TypedPrincipal{},
	}

	// Handle well-known SIDs
	if _, ok := BState().WellKnown.Get(sid); ok {
		group.ObjectIdentifier = baseProps.Domain + "-" + sid
	}

	// Handle SIDHistory
	if len(group.Properties.SIDHistory) > 0 {
		for _, historysid := range group.Properties.SIDHistory {
			group.HasSIDHistory = append(group.HasSIDHistory, ResolveSID(historysid, baseProps.Domain))
		}
	}

	// Extract additional properties if requested
	adminCount := entry.GetAttrVal("adminCount", "0") == "1"
	sam := entry.GetAttrVal("sAMAccountName", "")

	props := &group.Properties
	props.AdminCount = adminCount
	if sam != "" {
		props.SAMAccountName = sam
	}

	// Resolve group members
	members := entry.GetAttrVals("member", []string{})

	if len(members) > 0 {
		for _, m := range members {
			resolvedMember, ok := getMembership(m)
			if ok {
				group.Members = append(group.Members, resolvedMember)
			}
		}
	}

	group.Properties.IsACLProtected = group.IsACLProtected

	return group, true
}
