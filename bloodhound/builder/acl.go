package builder

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	gildap "github.com/Macmod/flashingestor/ldap"
	"github.com/TheManticoreProject/winacl/ace"
	"github.com/TheManticoreProject/winacl/ace/aceflags"
	"github.com/TheManticoreProject/winacl/ace/acetype"
	security "github.com/TheManticoreProject/winacl/securitydescriptor"
	"github.com/TheManticoreProject/winacl/securitydescriptor/control"
)

// ACEGuids maps well-known permission GUIDs to their logical names.
var ACEGuids = map[string]string{
	"AllGuid":                    "00000000-0000-0000-0000-000000000000",
	"GetChanges":                 "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
	"GetChangesAll":              "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
	"GetChangesInFilteredSet":    "89e95b76-444d-4c62-991a-0facbeda640c",
	"WriteMember":                "bf9679c0-0de6-11d0-a285-00aa003049e2",
	"MembershipPropertySet":      "bc0ac240-79a9-11d0-9020-00c04fc2d4cf",
	"UserForceChangePassword":    "00299570-246d-11d0-a768-00aa006e0529",
	"AllowedToAct":               "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79",
	"AddKeyPrincipal":            "5b47d60f-6090-40b2-9f37-2a4de88f3063",
	"UserAccountRestrictionsSet": "4c164200-20c0-11d0-a768-00aa006e0529",
	"WriteGPLink":                "f30e3bbe-9ff0-11d1-b603-0000f80367c1",
	"WriteSPN":                   "f3a64788-5306-11d1-a9c5-0000f80367c1",
	"PKINameFlag":                "ea1dddc4-60ff-416e-8cc0-17cee534bce7",
	"PKIEnrollmentFlag":          "d15ef7d8-f226-46db-ae79-b34e560bd12c",
	"Enroll":                     "0e10c968-78fb-11d2-90d4-00c04f79dc55",
}

// ACE represents a BloodHound-compatible access control entry.
type ACE struct {
	SID                                    string `json:"PrincipalSID"`
	PrincipalType                          string `json:"PrincipalType"`
	RightName                              string `json:"RightName"`
	Inherited                              bool   `json:"IsInherited"`
	InheritanceHash                        string `json:"InheritanceHash"`
	IsPermissionForOwnerRightsSid          bool   `json:"IsPermissionForOwnerRightsSid"`
	IsInheritedPermissionForOwnerRightsSid bool   `json:"IsInheritedPermissionForOwnerRightsSid"`
}

// newACE creates a new ACE with the given right name, SID, and inherited flag
func newACE(rightName, sid string, inherited bool, inheritanceHash string, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid bool) ACE {
	return ACE{
		RightName:                              rightName,
		SID:                                    sid,
		Inherited:                              inherited,
		PrincipalType:                          "",
		InheritanceHash:                        inheritanceHash,
		IsPermissionForOwnerRightsSid:          isPermissionForOwnerRightsSid,
		IsInheritedPermissionForOwnerRightsSid: isInheritedPermissionForOwnerRightsSid,
	}
}

// ActiveDirectoryRights flag constants
const (
	ADRightCreateChild          uint32 = 1        // 0x1
	ADRightDeleteChild          uint32 = 2        // 0x2
	ADRightListChildren         uint32 = 4        // 0x4
	ADRightSelf                 uint32 = 8        // 0x8
	ADRightReadProperty         uint32 = 16       // 0x10
	ADRightWriteProperty        uint32 = 32       // 0x20
	ADRightDeleteTree           uint32 = 64       // 0x40
	ADRightListObject           uint32 = 128      // 0x80
	ADRightExtendedRight        uint32 = 256      // 0x100
	ADRightDelete               uint32 = 65536    // 0x10000
	ADRightReadControl          uint32 = 131072   // 0x20000
	ADRightGenericExecute       uint32 = 131076   // 0x20004
	ADRightGenericWrite         uint32 = 131112   // 0x20028
	ADRightGenericRead          uint32 = 131220   // 0x20094
	ADRightWriteDacl            uint32 = 262144   // 0x40000
	ADRightWriteOwner           uint32 = 524288   // 0x80000
	ADRightGenericAll           uint32 = 983551   // 0xF01FF
	ADRightSynchronize          uint32 = 1048576  // 0x100000
	ADRightAccessSystemSecurity uint32 = 16777216 // 0x1000000
)

// maskToActiveDirectoryRightsString converts a mask value to its ActiveDirectoryRights string representation
func maskToActiveDirectoryRightsString(mask uint32) string {
	if mask == 0 {
		return "0"
	}

	// Define flags in order
	type flagPair struct {
		value uint32
		name  string
	}

	flags := []flagPair{
		{ADRightCreateChild, "CreateChild"},
		{ADRightDeleteChild, "DeleteChild"},
		{ADRightListChildren, "ListChildren"},
		{ADRightSelf, "Self"},
		{ADRightReadProperty, "ReadProperty"},
		{ADRightWriteProperty, "WriteProperty"},
		{ADRightDeleteTree, "DeleteTree"},
		{ADRightListObject, "ListObject"},
		{ADRightExtendedRight, "ExtendedRight"},
		{ADRightDelete, "Delete"},
		{ADRightReadControl, "ReadControl"},
		{ADRightGenericExecute, "GenericExecute"},
		{ADRightGenericWrite, "GenericWrite"},
		{ADRightGenericRead, "GenericRead"},
		{ADRightWriteDacl, "WriteDacl"},
		{ADRightWriteOwner, "WriteOwner"},
		{ADRightGenericAll, "GenericAll"},
		{ADRightSynchronize, "Synchronize"},
		{ADRightAccessSystemSecurity, "AccessSystemSecurity"},
	}

	var result []string

	for _, flag := range flags {
		if mask&flag.value == flag.value {
			result = append(result, flag.name)
		}
	}

	return strings.Join(result, ", ")
}

// CalculateInheritanceHash calculates the inheritance hash for an ACE
// This function is a direct translation of the original BloodHound code
func CalculateInheritanceHash(targetAce ace.AccessControlEntry) string {
	identity := targetAce.Identity.SID.String()

	mask := targetAce.Mask.RawValue
	aceRights := maskToActiveDirectoryRightsString(mask)

	aceType := strings.ToLower(targetAce.AccessControlObjectType.ObjectType.GUID.ToFormatD())

	inhObj := targetAce.AccessControlObjectType.InheritedObjectType.GUID.ToFormatD()

	hashInput := identity + aceRights + aceType + inhObj
	hash := sha1.Sum([]byte(hashInput))
	inheritanceHash := strings.ToUpper(hex.EncodeToString(hash[:]))
	return inheritanceHash
}

func (r *ACE) ResolvePrincipal(sidCache *StringCache, objectDomain string) {
	if r.PrincipalType != "" {
		return
	}

	// To obtain the domain for a principal, if needed:
	/*
		principalSid := r.SID
		domainSid := principalSid[:strings.LastIndex(principalSid, "-")]
		domain, ok := BState().SIDDomainCache.Get(domainSid)
		fmt.Fprintf(os.Stderr, "Looking up %s - %t\n", domainSid, ok)
		if !ok {
			domain = "UNKNOWN"
		}
	*/

	// First, check if it's a well-known SID
	if obj, ok := BState().WellKnown.Get(r.SID); ok {
		r.SID = fmt.Sprintf("%s-%s", strings.ToUpper(objectDomain), r.SID)
		r.PrincipalType = capitalize(obj.Type)
		return
	}

	// If it's not a well-known SID, try to resolve it from the SID cache
	sidEntry, ok := sidCache.Get(r.SID)
	if ok {
		r.PrincipalType = sidEntry.ToTypedPrincipal().ObjectType
		return
	}

	// If it's not in the SID cache, it means
	// it was not obtained during the initial ingestion,
	// therefore it shouldn't exist in this domain, its forest,
	// or any trusted domains (if recursion + searchforest are being used).

	// Otherwise, fake it
	r.PrincipalType = "Base"
}

// ResolveACETypes resolves the principal types for a list of ACEs
func ResolveACETypes(ACEs *[]ACE, sidCache *StringCache, objectDomain string) {
	for i := range *ACEs {
		(*ACEs)[i].ResolvePrincipal(sidCache, objectDomain)
	}
}

var allowedTypesWrite = []string{
	"user", "group", "computer", "gpo", "ou", "domain",
	"certtemplate", "rootca", "enterpriseca", "aiaca",
	"ntauthstore", "issuancepolicy",
}

// ParseBinaryACL parses an AD object's DACL into ACEs
func ParseBinaryACL(entryType string, entryDomain string, hasLAPS bool, aclData []byte) ([]ACE, bool, error) {
	if len(aclData) == 0 {
		return nil, false, nil
	}

	sd := security.NewSecurityDescriptor()
	_, err := sd.Unmarshal(aclData)
	if err != nil {
		return nil, false, err
	}

	isProtected := false
	sdControl, err := sd.Header.Control.Marshal()
	if err == nil {
		isProtected = binary.LittleEndian.Uint16(sdControl)&control.NT_SECURITY_DESCRIPTOR_CONTROL_PD != 0
	}

	var ACEs []ACE
	ownerSID := sd.Owner.SID

	// Can the SID not be present?
	sidStr := ownerSID.String()
	if !IgnoreSID(sidStr) {
		ACEs = append(ACEs, newACE("Owns", sidStr, false, "", false, false))
	}

	if sd.DACL == nil {
		return ACEs, isProtected, nil
	}

	for _, a := range sd.DACL.Entries {
		aceType := a.Header.Type.Value

		// TODO: Should we check if the ACE is empty?

		// 0x00 = ACCESS_ALLOWED_ACE
		// 0x05 = ACCESS_ALLOWED_OBJECT_ACE
		if aceType != acetype.ACE_TYPE_ACCESS_ALLOWED && aceType != acetype.ACE_TYPE_ACCESS_ALLOWED_OBJECT {
			// Only process access allowed ACEs
			continue
		}

		isInherited := a.IsInherited()
		hasInheritOnly := (a.Header.Flags.RawValue & aceflags.ACE_FLAG_INHERIT_ONLY) != 0
		objTypeGUID := strings.ToLower(a.AccessControlObjectType.ObjectType.GUID.ToFormatD())
		//hasObjectTypePresent := (a.Header.Flags.RawValue & flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT) != 0
		//hasInheritedObjectTypePresent := (a.Header.Flags.RawValue & flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT) != 0

		var entryTypeGUID string
		if val, ok := gildap.OBJECT_TYPE_GUID_MAP[entryType]; ok {
			entryTypeGUID = val
		}
		inheritedObjectTypeGUID := a.AccessControlObjectType.InheritedObjectType.GUID.ToFormatD()
		isAceInheritedFromCurrentType := isInherited && (strings.EqualFold(inheritedObjectTypeGUID, entryTypeGUID) || strings.EqualFold(inheritedObjectTypeGUID, ACEGuids["AllGuid"]))
		// Special case for Exchange (?)
		if !isInherited && !hasInheritOnly {
			isAceInheritedFromCurrentType = true
		}

		if !isAceInheritedFromCurrentType {
			continue
		}

		sidStr := a.Identity.SID.String()
		if IgnoreSID(sidStr) {
			continue
		}

		// Handle Owner Rights / InheritanceHash
		var isPermissionForOwnerRightsSid bool
		var isInheritedPermissionForOwnerRightsSid bool
		if sidStr == "S-1-3-4" {
			isPermissionForOwnerRightsSid = true
		}

		inheritanceHash := ""
		if isInherited {
			inheritanceHash = CalculateInheritanceHash(a)
			if isPermissionForOwnerRightsSid {
				isInheritedPermissionForOwnerRightsSid = true
			}
		}

		mask := a.Mask.RawValue

		// High-level rights
		if objTypeGUID == ACEGuids["AllGuid"] || objTypeGUID == "" {
			if mask&ADRightGenericAll == ADRightGenericAll {
				ACEs = append(ACEs, newACE("GenericAll", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
				continue
			}

			if mask&ADRightWriteDacl == ADRightWriteDacl {
				ACEs = append(ACEs, newACE("WriteDacl", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
			}

			if mask&ADRightWriteOwner == ADRightWriteOwner {
				ACEs = append(ACEs, newACE("WriteOwner", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
			}
		}

		// ACE courtesy of @rookuu according to SharpHound
		if mask&ADRightSelf == ADRightSelf &&
			mask&ADRightWriteProperty != ADRightWriteProperty &&
			mask&ADRightGenericWrite != ADRightGenericWrite &&
			entryType == "group" && (objTypeGUID == ACEGuids["WriteMember"] || objTypeGUID == ACEGuids["AllGuid"] || objTypeGUID == ACEGuids["MembershipPropertySet"]) {
			// Self add (ADS_RIGHT_DS_SELF)
			ACEs = append(ACEs, newACE("AddSelf", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
		}

		// Extended
		controlAccess := mask&ADRightExtendedRight == ADRightExtendedRight
		genericAll := mask&ADRightGenericAll == ADRightGenericAll
		if controlAccess || genericAll {
			switch entryType {
			case "domain":
				if objTypeGUID == ACEGuids["GetChanges"] {
					ACEs = append(ACEs, newACE("GetChanges", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
				} else if objTypeGUID == ACEGuids["GetChangesAll"] {
					ACEs = append(ACEs, newACE("GetChangesAll", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
				} else if objTypeGUID == ACEGuids["GetChangesInFilteredSet"] {
					ACEs = append(ACEs, newACE("GetChangesInFilteredSet", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
				} else if objTypeGUID == ACEGuids["AllGuid"] || objTypeGUID == "" {
					ACEs = append(ACEs, newACE("AllExtendedRights", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
				}
			case "user":
				if objTypeGUID == ACEGuids["UserForceChangePassword"] {
					ACEs = append(ACEs, newACE("ForceChangePassword", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
				} else if objTypeGUID == ACEGuids["AllGuid"] || objTypeGUID == "" {
					ACEs = append(ACEs, newACE("AllExtendedRights", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
				}
			case "computer":
				if hasLAPS {
					if objTypeGUID == ACEGuids["AllGuid"] || objTypeGUID == "" {
						ACEs = append(ACEs, newACE("AllExtendedRights", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
					} else {
						objType := a.AccessControlObjectType.ObjectType.GUID.ToFormatD()

						entryForest := BState().GetForestRoot(entryDomain)

						mcsGUID, _ := BState().AttrGUIDMap.Load(entryForest + "+ms-mcs-admpwd")
						lapsGUID, _ := BState().AttrGUIDMap.Load(entryForest + "+ms-laps-password")
						encryptedGUID, _ := BState().AttrGUIDMap.Load(entryForest + "+ms-laps-encryptedpassword")

						if (mcsGUID != nil && strings.EqualFold(objType, mcsGUID.(string))) ||
							(lapsGUID != nil && strings.EqualFold(objType, lapsGUID.(string))) ||
							(encryptedGUID != nil && strings.EqualFold(objType, encryptedGUID.(string))) {
							ACEs = append(ACEs, newACE("ReadLAPSPassword", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
						}
					}
				}
			case "certtemplate":
				if objTypeGUID == ACEGuids["AllGuid"] || objTypeGUID == "" {
					ACEs = append(ACEs, newACE("AllExtendedRights", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
				} else if objTypeGUID == ACEGuids["Enroll"] {
					ACEs = append(ACEs, newACE("Enroll", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
				}
			}
		}

		// Writes
		if mask&ADRightGenericWrite == ADRightGenericWrite ||
			mask&ADRightWriteProperty == ADRightWriteProperty ||
			mask&ADRightGenericAll == ADRightGenericAll {
			if slices.Contains(allowedTypesWrite, entryType) &&
				(objTypeGUID == ACEGuids["AllGuid"] || objTypeGUID == "") {
				ACEs = append(ACEs, newACE("GenericWrite", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
			}
			if entryType == "user" && objTypeGUID == ACEGuids["WriteSPN"] {
				ACEs = append(ACEs, newACE("WriteSPN", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
			}
			if entryType == "computer" && objTypeGUID == ACEGuids["AllowedToAct"] {
				ACEs = append(ACEs, newACE("AddAllowedToAct", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
			}
			if entryType == "computer" && objTypeGUID == ACEGuids["UserAccountRestrictionsSet"] {
				ACEs = append(ACEs, newACE("WriteAccountRestrictions", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
			}
			if (entryType == "ou" || entryType == "domain") && objTypeGUID == ACEGuids["WriteGPLink"] {
				ACEs = append(ACEs, newACE("WriteGPLink", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
			}
			if entryType == "group" && (objTypeGUID == ACEGuids["WriteMember"] || objTypeGUID == ACEGuids["MembershipPropertySet"]) {
				ACEs = append(ACEs, newACE("AddMember", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
			}
			if (entryType == "user" || entryType == "computer") && objTypeGUID == ACEGuids["AddKeyPrincipal"] {
				ACEs = append(ACEs, newACE("AddKeyCredentialLink", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
			}
			if entryType == "certtemplate" {
				if objTypeGUID == ACEGuids["PKIEnrollmentFlag"] {
					ACEs = append(ACEs, newACE("WritePKIEnrollmentFlag", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
				} else if objTypeGUID == ACEGuids["PKINameFlag"] {
					ACEs = append(ACEs, newACE("WritePKINameFlag", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
				}
			}
		}

		// CA rights
		if entryType == "enterpriseca" {
			if objTypeGUID == ACEGuids["Enroll"] {
				ACEs = append(ACEs, newACE("Enroll", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
			}

			if mask&0x1 != 0 {
				// ManageCA
				ACEs = append(ACEs, newACE("ManageCA", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
			}
			if mask&0x2 != 0 {
				// ManageCertificates
				ACEs = append(ACEs, newACE("ManageCertificates", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
			}
			if mask&0x200 != 0 {
				// Enroll
				ACEs = append(ACEs, newACE("Enroll", sidStr, isInherited, inheritanceHash, isPermissionForOwnerRightsSid, isInheritedPermissionForOwnerRightsSid))
			}
		}
	}

	return ACEs, isProtected, nil
}

// ParseGMSAReaders parses GMSA (Group Managed Service Account) readers from the msDS-GroupMSAMembership attribute
func ParseGMSAReaders(gmsaBytes []byte, objectName string) ([]ACE, error) {
	if len(gmsaBytes) == 0 {
		return nil, nil
	}

	sd := security.NewSecurityDescriptor()
	_, err := sd.Unmarshal(gmsaBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal GMSA security descriptor for %s: %w", objectName, err)
	}

	var ACEs []ACE

	if sd.DACL == nil {
		return ACEs, nil
	}

	for _, a := range sd.DACL.Entries {
		aceType := a.Header.Type.Value

		// Only process ACCESS_ALLOWED ACEs
		if aceType != acetype.ACE_TYPE_ACCESS_ALLOWED && aceType != acetype.ACE_TYPE_ACCESS_ALLOWED_OBJECT {
			continue
		}

		sidStr := a.Identity.SID.String()
		if IgnoreSID(sidStr) {
			continue
		}

		isInherited := a.IsInherited()

		ACEs = append(ACEs, newACE("ReadGMSAPassword", sidStr, isInherited, "", false, false))
	}

	return ACEs, nil
}

func IgnoreSID(s string) bool {
	ignores := []string{"S-1-3-0", "S-1-5-18", "S-1-5-10"}
	for _, v := range ignores {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// ACEForHashing represents an ACE structure optimized for consistent hashing and sorting
type ACEForHashing struct {
	AccessControlType   string // "Allow" or "Deny"
	IdentityReference   string // SID string
	Rights              string // Numeric rights value
	ObjectType          string // GUID string (empty if not object-specific)
	InheritedObjectType string // GUID string (empty if not inherited-object-specific)
	InheritanceFlags    string // Numeric inheritance flags
}

// String returns the semicolon-separated representation of the ACE for hashing
func (a ACEForHashing) String() string {
	return fmt.Sprintf("%s;%s;%s;%s;%s;%s",
		a.AccessControlType,
		a.IdentityReference,
		a.Rights,
		a.ObjectType,
		a.InheritedObjectType,
		a.InheritanceFlags)
}

// CalculateImplicitACLHash calculates a SHA1 hash of non-inherited ACEs combined with DACL protection status
// This is used to detect AdminSDHolder protection by comparing object ACL hashes
func CalculateImplicitACLHash(securityDescriptor []byte) (string, error) {
	if len(securityDescriptor) == 0 {
		return "", nil
	}

	sd := security.NewSecurityDescriptor()
	_, err := sd.Unmarshal(securityDescriptor)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal security descriptor: %w", err)
	}

	// Check DACL protection status
	daclProtected := false
	sdControl, err := sd.Header.Control.Marshal()
	if err == nil {
		daclProtected = binary.LittleEndian.Uint16(sdControl)&control.NT_SECURITY_DESCRIPTOR_CONTROL_PD != 0
	}

	var aces []ACEForHashing

	if sd.DACL != nil {
		for _, a := range sd.DACL.Entries {
			// Skip inherited ACEs - we only want explicit ACEs
			if a.IsInherited() {
				continue
			}

			// Determine access control type
			aceType := a.Header.Type.Value
			var accessControlType string
			if aceType == acetype.ACE_TYPE_ACCESS_ALLOWED || aceType == acetype.ACE_TYPE_ACCESS_ALLOWED_OBJECT {
				accessControlType = "Allow"
			} else if aceType == acetype.ACE_TYPE_ACCESS_DENIED || aceType == acetype.ACE_TYPE_ACCESS_DENIED_OBJECT {
				accessControlType = "Deny"
			} else {
				// Skip other ACE types (audit, alarm, etc.)
				continue
			}

			// Get SID
			sidStr := a.Identity.SID.String()

			// Get access mask (rights)
			rights := fmt.Sprintf("%d", a.Mask.RawValue)

			// Get ObjectType GUID (for object-specific ACEs)
			objectType := ""
			if aceType == acetype.ACE_TYPE_ACCESS_ALLOWED_OBJECT || aceType == acetype.ACE_TYPE_ACCESS_DENIED_OBJECT {
				objectType = a.AccessControlObjectType.ObjectType.GUID.ToFormatD()
			}

			// Get InheritedObjectType GUID
			inheritedObjectType := ""
			if aceType == acetype.ACE_TYPE_ACCESS_ALLOWED_OBJECT || aceType == acetype.ACE_TYPE_ACCESS_DENIED_OBJECT {
				inheritedObjectType = a.AccessControlObjectType.InheritedObjectType.GUID.ToFormatD()
			}

			// Get inheritance flags
			inheritanceFlags := fmt.Sprintf("%d", a.Header.Flags.RawValue)

			aces = append(aces, ACEForHashing{
				AccessControlType:   accessControlType,
				IdentityReference:   sidStr,
				Rights:              rights,
				ObjectType:          objectType,
				InheritedObjectType: inheritedObjectType,
				InheritanceFlags:    inheritanceFlags,
			})
		}
	}

	// Sort ACEs for consistent ordering
	// Sort by: AccessControlType, IdentityReference, Rights, ObjectType, InheritedObjectType, InheritanceFlags
	slices.SortFunc(aces, func(i, j ACEForHashing) int {
		if i.AccessControlType != j.AccessControlType {
			return strings.Compare(i.AccessControlType, j.AccessControlType)
		}
		if i.IdentityReference != j.IdentityReference {
			return strings.Compare(i.IdentityReference, j.IdentityReference)
		}
		if i.Rights != j.Rights {
			return strings.Compare(i.Rights, j.Rights)
		}
		if i.ObjectType != j.ObjectType {
			return strings.Compare(i.ObjectType, j.ObjectType)
		}
		if i.InheritedObjectType != j.InheritedObjectType {
			return strings.Compare(i.InheritedObjectType, j.InheritedObjectType)
		}
		return strings.Compare(i.InheritanceFlags, j.InheritanceFlags)
	})

	// Build string representation
	var aceStrings []string
	for _, ace := range aces {
		aceStrings = append(aceStrings, ace.String())
	}

	// Concatenate with semicolons and append DACL protection status
	concatenated := strings.Join(aceStrings, ";")
	if daclProtected {
		concatenated += "|DaclProtected:true"
	} else {
		concatenated += "|DaclProtected:false"
	}

	// Calculate SHA1 hash
	hash := sha1.Sum([]byte(concatenated))
	return strings.ToUpper(fmt.Sprintf("%x", hash)), nil
}

// IsAdminSDHolderProtected checks if an object's ACL matches the AdminSDHolder ACL hash
// Returns true if the object is protected by AdminSDHolder
func IsAdminSDHolderProtected(securityDescriptor []byte, adminSdHolderHash, objectName string) (bool, error) {
	if len(securityDescriptor) == 0 || adminSdHolderHash == "" {
		return false, nil
	}

	// Calculate the implicit ACL hash for this object
	objectHash, err := CalculateImplicitACLHash(securityDescriptor)
	if err != nil {
		return false, fmt.Errorf("failed to calculate ACL hash for %s: %w", objectName, err)
	}

	// Case-insensitive comparison
	return strings.EqualFold(objectHash, adminSdHolderHash), nil
}

// GetInheritedAceHashes calculates inheritance hashes from ACEs that will be inherited down the tree
// This function processes the security descriptor and returns unique inheritance hashes
// from ACEs that have inheritance flags set
func GetInheritedAceHashes(securityDescriptor []byte) []string {
	if len(securityDescriptor) == 0 {
		return nil
	}

	sd := security.NewSecurityDescriptor()
	_, err := sd.Unmarshal(securityDescriptor)
	if err != nil {
		return nil
	}

	if sd.DACL == nil {
		return nil
	}

	var hashes []string
	seenHashes := make(map[string]bool)

	for _, a := range sd.DACL.Entries {
		// Skip inherited ACEs
		if a.IsInherited() {
			continue
		}

		// Skip deny ACEs
		aceType := a.Header.Type.Value
		if aceType != acetype.ACE_TYPE_ACCESS_ALLOWED && aceType != acetype.ACE_TYPE_ACCESS_ALLOWED_OBJECT {
			continue
		}

		// Skip filtered SIDs
		sidStr := a.Identity.SID.String()
		if IgnoreSID(sidStr) {
			continue
		}

		// Check if this ACE has inheritance flags set (will be inherited by children)
		inheritanceFlags := a.Header.Flags.RawValue & (aceflags.ACE_FLAG_CONTAINER_INHERIT | aceflags.ACE_FLAG_OBJECT_INHERIT)
		if inheritanceFlags == 0 {
			continue
		}

		// Calculate inheritance hash for this ACE
		hash := CalculateInheritanceHash(a)
		if hash == "" {
			continue
		}

		// Skip if we've already seen this hash
		if seenHashes[hash] {
			continue
		}

		// Add the hash
		hashes = append(hashes, hash)
		seenHashes[hash] = true
	}

	return hashes
}
