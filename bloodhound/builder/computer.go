package builder

import (
	"strconv"
	"strings"

	gildap "github.com/Macmod/flashingestor/ldap"
)

// BuildComputerFromEntry constructs a Computer object from an LDAP entry.
func BuildComputerFromEntry(entry *gildap.LDAPEntry) (*Computer, bool) {
	var baseObj BaseADObject
	baseObj.FromEntry(entry, "computer")

	var baseProps BaseProperties
	baseProps.FromEntry(entry)
	baseProps.SetOwnerRightsFlags(baseObj.Aces)

	compName := entry.GetAttrVal("dNSHostName", "")
	shortName := strings.TrimRight(entry.GetAttrVal("sAMAccountName", ""), "$")
	if compName == "" && shortName != "" {
		compName = shortName + "." + baseProps.Domain
	}
	if compName == "" {
		cn := entry.GetAttrVal("cn", "")
		compName = cn + "." + baseProps.Domain
	}
	if compName == "" {
		name := entry.GetAttrVal("name", "")
		compName = name + "." + baseProps.Domain
	}
	if compName == "" {
		compName = "UNKNOWN." + baseProps.Domain
	}

	objectSID := entry.GetSID()
	primaryGroupId := entry.GetAttrVal("primaryGroupID", "")
	objectSidSlice := strings.Split(objectSID, "-")
	extractedDomainSid := strings.Join(objectSidSlice[:len(objectSidSlice)-1], "-")
	primaryGroupSid := extractedDomainSid + "-" + primaryGroupId

	delegateHosts := entry.GetAttrVals("msDS-AllowedToDelegateTo", []string{})
	uac := entry.GetUAC()

	lastLogonTimestampStr := entry.GetAttrVal("lastLogonTimestamp", "0")
	lastLogonTimestamp := gildap.FormatTime2(lastLogonTimestampStr)
	if lastLogonTimestampStr == "0" {
		lastLogonTimestamp = int64(-1)
	}

	spns := entry.GetAttrVals("servicePrincipalName", []string{})
	if len(spns) == 0 {
		spns = []string{}
	}

	osname := entry.GetAttrVal("operatingSystem", "")
	ossp := entry.GetAttrVal("operatingSystemServicePack", "")
	operatingSystem := osname
	if ossp != "" {
		operatingSystem = osname + " " + ossp
	}

	// Check AdminSDHolder protection
	adminSDHolderProtected := false
	securityDescriptor := entry.GetAttrRawVal("nTSecurityDescriptor", []byte{})
	if adminHashVal, ok := BState().AdminSDHolderHashCache.Load(baseProps.Domain); ok && len(securityDescriptor) > 0 {
		adminHash := adminHashVal.(string)
		isProtected, err := IsAdminSDHolderProtected(securityDescriptor, adminHash, strings.ToUpper(compName))
		if err == nil {
			adminSDHolderProtected = isProtected
		}
	}

	props := ComputerProperties{
		BaseProperties:           baseProps,
		Name:                     strings.ToUpper(compName),
		SAMAccountName:           entry.GetAttrVal("sAMAccountName", ""),
		Email:                    entry.GetAttrVal("mail", ""),
		Enabled:                  (uac & 2) == 0,
		UnconstrainedDelegation:  (uac & 0x00080000) == 0x00080000,
		TrustedToAuth:            (uac & 0x01000000) == 0x01000000,
		IsDC:                     (uac & 0x2000) == 0x2000,
		IsReadOnlyDC:             (uac & 0x04000000) == 0x04000000,
		EncryptedTextPwdAllowed:  (uac & 0x0080) == 0x0080,
		UseDesKeyOnly:            (uac & 0x00200000) == 0x00200000,
		LogonScriptEnabled:       (uac & 0x0001) == 0x0001,
		LockedOut:                (uac & 0x0010) == 0x0010,
		PasswordExpired:          (uac & 0x00800000) == 0x00800000,
		SupportedEncryptionTypes: ConvertEncryptionTypes(entry.GetAttrVal("msDS-SupportedEncryptionTypes", "")),
		AdminCount:               entry.GetAttrVal("adminCount", "0") != "0",
		UserAccountControl:       int64(uac),
		ObjectGUID:               entry.GetGUID(),
		HasLAPS:                  entry.HasLAPS(),
		LastLogon:                gildap.FormatTime2(entry.GetAttrVal("lastLogon", "0")),
		LastLogonTimestamp:       lastLogonTimestamp,
		PwdLastSet:               gildap.FormatTime2(entry.GetAttrVal("pwdLastSet", "0")),
		ServicePrincipalNames:    spns,
		OperatingSystem:          operatingSystem,
		SIDHistory:               entry.GetAttrVals("sIDHistory", []string{}),
		AllowedToDelegate:        delegateHosts,
		AdminSDHolderProtected:   adminSDHolderProtected,
	}

	var computer Computer
	computer.BaseADObject = baseObj
	computer.PrimaryGroupSID = primaryGroupSid
	computer.Properties = props
	computer.DomainSID = computer.Properties.DomainSID
	computer.UnconstrainedDelegation = computer.Properties.UnconstrainedDelegation

	computer.IsDC = computer.Properties.IsDC // Handle DumpSMSAPassword
	hsa := entry.GetAttrVals("msDS-HostServiceAccount", []string{})

	for _, attr := range hsa {
		smsa, ok := BState().MemberCache.Get(attr)
		if ok {
			computer.DumpSMSAPassword = append(
				computer.DumpSMSAPassword, smsa.ToTypedPrincipal(),
			)
		}
	}

	// Handle SIDHistory
	if len(computer.Properties.SIDHistory) > 0 {
		for _, historysid := range computer.Properties.SIDHistory {
			computer.HasSIDHistory = append(computer.HasSIDHistory, ResolveSID(historysid, baseProps.Domain))
		}
	}

	seenTargets := make(map[string]struct{})

	if len(computer.Properties.AllowedToDelegate) > 0 {
		for _, target := range computer.Properties.AllowedToDelegate {
			resolvedTargetSid, ok := ResolveSpn(target, baseProps.Domain)
			if !ok {
				// TODO: Review what to do in this case?
				continue
			}

			if _, seen := seenTargets[resolvedTargetSid]; seen {
				continue
			}
			computer.AllowedToDelegate = append(computer.AllowedToDelegate, TypedPrincipal{
				ObjectIdentifier: resolvedTargetSid,
				ObjectType:       "Computer",
			})
			seenTargets[resolvedTargetSid] = struct{}{}
		}
	}

	computer.Properties.IsACLProtected = computer.IsACLProtected

	// Handle RBCD information
	entryDomain := entry.GetDomainFromDN()
	securityDescriptorRBCD := entry.GetAttrRawVal("msDS-AllowedToActOnBehalfOfOtherIdentity", nil)

	parsedACLsOnBehalf, _, _ := ParseBinaryACL(
		"computer", entryDomain, false,
		securityDescriptorRBCD,
	)

	for _, delegated := range parsedACLsOnBehalf {
		if delegated.RightName == "Owner" {
			continue
		}
		if delegated.RightName == "GenericAll" {
			resolvedSID := ResolveSID(delegated.SID, baseProps.Domain)
			computer.AllowedToAct = append(computer.AllowedToAct, TypedPrincipal{
				ObjectIdentifier: resolvedSID.ObjectIdentifier,
				ObjectType:       resolvedSID.ObjectType,
			})
		}
	}

	return &computer, true
}

func ConvertEncryptionTypes(encryptionTypesStr string) []string {
	if encryptionTypesStr == "" {
		return nil
	}

	encryptionTypesInt, err := strconv.ParseInt(encryptionTypesStr, 10, 64)
	if err != nil {
		encryptionTypesInt = 0
	}

	supportedEncryptionTypes := []string{}
	if encryptionTypesInt == 0 {
		supportedEncryptionTypes = append(supportedEncryptionTypes, "Not defined")
		return supportedEncryptionTypes
	}

	if (encryptionTypesInt & 0x01) == 0x01 {
		supportedEncryptionTypes = append(supportedEncryptionTypes, "DES-CBC-CRC")
	}

	if (encryptionTypesInt & 0x02) == 0x02 {
		supportedEncryptionTypes = append(supportedEncryptionTypes, "DES-CBC-MD5")
	}

	if (encryptionTypesInt & 0x04) == 0x04 {
		supportedEncryptionTypes = append(supportedEncryptionTypes, "RC4-HMAC-MD5")
	}

	if (encryptionTypesInt & 0x08) == 0x08 {
		supportedEncryptionTypes = append(supportedEncryptionTypes, "AES128-CTS-HMAC-SHA1-96")
	}

	if (encryptionTypesInt & 0x10) == 0x10 {
		supportedEncryptionTypes = append(supportedEncryptionTypes, "AES256-CTS-HMAC-SHA1-96")
	}

	return supportedEncryptionTypes
}
