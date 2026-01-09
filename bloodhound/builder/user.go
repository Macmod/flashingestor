package builder

import (
	"fmt"
	"strings"

	gildap "github.com/Macmod/flashingestor/ldap"
)

// BuildUserFromEntry constructs a User object from an LDAP entry.
func BuildUserFromEntry(entry *gildap.LDAPEntry) (*User, bool) {
	var baseObj BaseADObject
	baseObj.FromEntry(entry, "user")

	var baseProps BaseProperties
	baseProps.FromEntry(entry)
	baseProps.SetOwnerRightsFlags(baseObj.Aces)

	// Include GMSA readers if the attribute is present
	gmsaBytes := entry.GetAttrRawVal("msDS-GroupMSAMembership", []byte{})
	if len(gmsaBytes) > 0 {
		gmsaAces, err := ParseGMSAReaders(gmsaBytes, baseObj.ObjectIdentifier)
		ResolveACETypes(&gmsaAces, BState().SIDCache, baseProps.Domain)
		if err == nil {
			baseObj.Aces = append(baseObj.Aces, gmsaAces...)
		}
	}

	samAccountName := entry.GetAttrVal("sAMAccountName", "")
	userName := strings.ToUpper(samAccountName) + "@" + baseProps.Domain

	uac := entry.GetUAC()
	delegateHosts := entry.GetAttrVals("msDS-AllowedToDelegateTo", []string{})

	// Check AdminSDHolder protection
	adminSDHolderProtected := false
	securityDescriptor := entry.GetAttrRawVal("nTSecurityDescriptor", []byte{})
	if adminHashVal, ok := BState().AdminSDHolderHashCache.Load(baseProps.Domain); ok && len(securityDescriptor) > 0 {
		adminHash := adminHashVal.(string)
		isProtected, err := IsAdminSDHolderProtected(securityDescriptor, adminHash, userName)
		if err == nil {
			adminSDHolderProtected = isProtected
		}
	}

	props := UserProperties{
		BaseProperties:          baseProps,
		Name:                    userName,
		UnconstrainedDelegation: uac&0x00080000 == 0x00080000,
		TrustedToAuth:           uac&0x01000000 == 0x01000000,
		PasswordNotReqd:         uac&0x00000020 == 0x00000020,
		Enabled:                 uac&2 == 0,
		LastLogon:               formatTime2(entry.GetAttrVal("lastLogon", "0")),          // raw
		LastLogonTimestamp:      formatTime2(entry.GetAttrVal("lastLogonTimestamp", "0")), // raw
		PwdLastSet:              formatTime2(entry.GetAttrVal("pwdLastSet", "0")),         // raw
		DontReqPreauth:          uac&0x00400000 == 0x00400000,
		PwdNeverExpires:         uac&0x00010000 == 0x00010000,
		Sensitive:               uac&0x00100000 == 0x00100000,
		ServicePrincipalNames:   entry.GetAttrVals("servicePrincipalName", []string{}),
		DisplayName:             entry.GetAttrVal("displayName", ""),
		Email:                   entry.GetAttrVal("mail", ""),
		Title:                   entry.GetAttrVal("title", ""),
		HomeDirectory:           entry.GetAttrVal("homeDirectory", ""),
		UserPassword:            entry.GetAttrVal("userPassword", ""),
		AdminCount:              entry.GetAttrVal("adminCount", "0") == "1",
		UnixPassword:            entry.GetAttrVal("unixUserPassword", ""),
		UnicodePassword:         entry.GetAttrVal("unicodePwd", ""),
		LogonScript:             entry.GetAttrVal("scriptPath", ""),
		SAMAccountName:          entry.GetAttrVal("sAMAccountName", ""),
		SFUPassword:             entry.GetAttrVal("msSFU30Password", ""),
		AllowedToDelegate:       delegateHosts,
		SIDHistory:              entry.GetAttrVals("sIDHistory", []string{}), // Should we encode the SIDs or not?
		AdminSDHolderProtected:  adminSDHolderProtected,
	}

	objectSid := entry.GetSID()

	var primaryGroupSid string
	primaryGroupId := entry.GetAttrVal("primaryGroupID", "")

	objectSidSlice := strings.Split(objectSid, "-")
	extractedDomainSid := strings.Join(objectSidSlice[:len(objectSidSlice)-1], "-")

	primaryGroupSid = extractedDomainSid + "-" + primaryGroupId

	user := User{
		BaseADObject:            baseObj,
		AllowedToDelegate:       []TypedPrincipal{},
		PrimaryGroupSID:         primaryGroupSid,
		UnconstrainedDelegation: props.UnconstrainedDelegation,
		Properties:              props,
		SPNTargets:              []SPNPrivilege{},
		HasSIDHistory:           []TypedPrincipal{},
		DomainSID:               extractedDomainSid,
	}

	// Handle SIDHistory
	if len(user.Properties.SIDHistory) > 0 {
		for _, historysid := range user.Properties.SIDHistory {
			user.HasSIDHistory = append(user.HasSIDHistory, ResolveSID(historysid, baseProps.Domain))
		}
	}

	// Handle AllowedToDelegate
	seenTargets := make(map[string]struct{})

	if len(props.AllowedToDelegate) > 0 {
		for _, target := range props.AllowedToDelegate {
			resolvedTargetSid, ok := ResolveSpn(target, baseProps.Domain)
			if !ok {
				// TODO: Review what to do in this case?
				continue
			}

			if _, seen := seenTargets[resolvedTargetSid]; seen {
				continue
			}

			user.AllowedToDelegate = append(user.AllowedToDelegate, TypedPrincipal{
				ObjectIdentifier: resolvedTargetSid,
				ObjectType:       "Computer",
			})

			seenTargets[resolvedTargetSid] = struct{}{}
		}
	}

	// Handle SPNTargets
	for _, spn := range props.ServicePrincipalNames {
		if strings.Contains(spn, "@") {
			continue
		}

		if strings.Contains(strings.ToLower(spn), "mssqlsvc") {
			port := 1433
			if strings.Contains(spn, ":") {
				splitSPN := strings.SplitN(spn, ":", 2)
				if len(splitSPN) == 2 {
					_, err := fmt.Sscanf(splitSPN[1], "%d", &port)
					if err != nil {
						port = 1433
					}
				}
			}

			hostSid, ok := ResolveSpn(spn, baseProps.Domain)

			if ok && strings.HasPrefix(hostSid, "S-1") {
				user.SPNTargets = append(user.SPNTargets, SPNPrivilege{
					ComputerSID: hostSid,
					Port:        port,
					Service:     "SQLAdmin",
				})
			}
		}
	}

	props.HasSPN = len(props.ServicePrincipalNames) > 0
	if props.LastLogonTimestamp == 0 {
		props.LastLogonTimestamp = -1
	}

	user.Properties.IsACLProtected = user.IsACLProtected

	return &user, true
}
