package bloodhound

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/config"
	"github.com/Macmod/flashingestor/msrpc"
	"github.com/TheManticoreProject/winacl/ace"
	"github.com/TheManticoreProject/winacl/ace/acetype"
	"github.com/TheManticoreProject/winacl/securitydescriptor"
	"github.com/TheManticoreProject/winacl/sid"
	"github.com/oiweiwei/go-msrpc/msrpc/samr/samr/v1"
)

// CertAbuseProcessor collects and processes certificate authority security data,
// including enrollment permissions and related abuse vectors.
type CertAbuseProcessor struct {
	domain   string
	msrpcObj *msrpc.MSRPC
	auth     *config.CredentialMgr
}

// NewCertAbuseProcessor creates a processor for the specified domain.
// Returns nil if the WinReg client binding fails.
func NewCertAbuseProcessor(domain string, msrpcObj *msrpc.MSRPC, auth *config.CredentialMgr) *CertAbuseProcessor {
	err := msrpcObj.BindWinregClient()
	if err != nil {
		return nil
	}

	return &CertAbuseProcessor{
		domain:   domain,
		msrpcObj: msrpcObj,
		auth:     auth,
	}
}

// ProcessRegistryEnrollmentPermissions retrieves CA security from the registry,
// including ownership and management rights ACEs.
func (cap *CertAbuseProcessor) ProcessRegistryEnrollmentPermissions(
	ctx context.Context,
	caName string,
	computerName string,
	computerObjectId string,
	objectDomain string,
) builder.AceRegistryAPIResult {
	result := builder.AceRegistryAPIResult{}

	//fmt.Fprintf(os.Stderr, "Processing CA Security for CA: %s on Computer: %s with Args: %s %s\n", caName, computerName, computerObjectId, objectDomain)
	aceData := cap.GetCASecurity(caName)
	result.Collected = aceData.Collected
	if !result.Collected {
		result.FailureReason = aceData.FailureReason
		return result
	}

	if aceData.Value == nil {
		return result
	}

	sd := &securitydescriptor.NtSecurityDescriptor{}
	_, err := sd.Unmarshal(aceData.Value)
	if err != nil {
		errStr := fmt.Sprint(err)
		result.FailureReason = &errStr
		result.Collected = false
		return result
	}

	isDomainController := cap.isDomainController(computerObjectId)
	machineSid := cap.getMachineSid(ctx, computerName, computerObjectId)

	var aces []builder.ACE

	// Process owner
	if sd.Owner != nil {
		ownerSid := sd.Owner.SID.String()
		if ownerSid != "" {
			resolvedOwner, success := cap.getRegistryPrincipal(
				ownerSid, objectDomain,
				isDomainController, computerObjectId, machineSid,
			)
			if success {
				aces = append(aces, builder.ACE{
					PrincipalType: resolvedOwner.ObjectType,
					SID:           resolvedOwner.ObjectIdentifier,
					RightName:     "Owns",
					Inherited:     false,
				})
			} else {
				aces = append(aces, builder.ACE{
					PrincipalType: "Base",
					SID:           ownerSid,
					RightName:     "Owns",
					Inherited:     false,
				})
			}
		}
	}

	// Process access rules from DACL
	if sd.DACL != nil {
		for _, ace := range sd.DACL.Entries {
			// Skip deny ACEs
			if ace.Header.Type.Value == acetype.ACE_TYPE_ACCESS_DENIED {
				continue
			}

			principalSid := ace.Identity.SID.String()
			if principalSid == "" || builder.IgnoreSID(principalSid) {
				continue
			}

			principalDomainSid := principalSid[:strings.LastIndex(principalSid, "-")]
			principalDomain, ok := builder.BState().SIDDomainCache.Get(principalDomainSid)
			if !ok {
				principalDomain = objectDomain
			}

			resolvedPrincipal, resSuccess := cap.getRegistryPrincipal(
				principalSid, principalDomain,
				isDomainController, computerObjectId, machineSid,
			)
			if !resSuccess {
				resolvedPrincipal = builder.TypedPrincipal{
					ObjectType:       "Base",
					ObjectIdentifier: principalSid,
				}
			}

			isInherited := ace.IsInherited()
			caRights := ace.Mask.RawValue

			// Check for ManageCA
			if (caRights & 0x00000001) != 0 {
				aces = append(aces, builder.ACE{
					PrincipalType: resolvedPrincipal.ObjectType,
					SID:           resolvedPrincipal.ObjectIdentifier,
					Inherited:     isInherited,
					RightName:     "ManageCA",
				})
			}

			// Check for ManageCertificates
			if (caRights & 0x00000002) != 0 {
				aces = append(aces, builder.ACE{
					PrincipalType: resolvedPrincipal.ObjectType,
					SID:           resolvedPrincipal.ObjectIdentifier,
					Inherited:     isInherited,
					RightName:     "ManageCertificates",
				})
			}

			// Check for Enroll
			if (caRights & 0x00000100) != 0 {
				aces = append(aces, builder.ACE{
					PrincipalType: resolvedPrincipal.ObjectType,
					SID:           resolvedPrincipal.ObjectIdentifier,
					Inherited:     isInherited,
					RightName:     "Enroll",
				})
			}
		}
	}

	result.Data = aces
	return result
}

// ProcessEAPermissions retrieves enrollment agent restrictions from a CA
func (cap *CertAbuseProcessor) ProcessEAPermissions(
	ctx context.Context,
	caName string,
	computerName string,
	computerObjectId string,
	objectDomain string,
) builder.EnrollmentAgentRegistryAPIResult {
	result := builder.EnrollmentAgentRegistryAPIResult{}

	regData := cap.GetEnrollmentAgentRights(caName)
	result.Collected = regData.Collected
	if !result.Collected {
		result.FailureReason = regData.FailureReason
		return result
	}

	if regData.Value == nil {
		return result
	}

	isDomainController := cap.isDomainController(computerObjectId)
	machineSid := cap.getMachineSid(ctx, computerName, computerObjectId)

	// Parse security descriptor using winacl
	sd := &securitydescriptor.NtSecurityDescriptor{}
	_, err := sd.Unmarshal(regData.Value)
	if err != nil {
		errStr := fmt.Sprint(err)
		result.FailureReason = &errStr
		result.Collected = false
		return result
	}

	var enrollmentAgentRestrictions []builder.EnrollmentAgentRestriction

	// Iterate through DACL
	if sd.DACL != nil {
		for _, ace := range sd.DACL.Entries {
			restriction, success := cap.createEnrollmentAgentRestriction(
				&ace, objectDomain, computerName,
				isDomainController, computerObjectId, machineSid,
			)
			if success {
				enrollmentAgentRestrictions = append(enrollmentAgentRestrictions, restriction)
			}
		}
	}

	result.Restrictions = enrollmentAgentRestrictions
	return result
}

// GetCASecurity retrieves CA security registry value from the remote machine
func (cap *CertAbuseProcessor) GetCASecurity(caName string) builder.RegistryAPIResult {
	result := builder.RegistryAPIResult{}

	regSubKey := fmt.Sprintf("SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\%s", caName)
	regValue := "Security"

	data, err := cap.msrpcObj.GetRegistryKeyData(regSubKey, regValue)
	if err != nil {
		errStr := fmt.Sprint(err)
		result.FailureReason = &errStr
		return result
	}

	result.Collected = true

	// TODO: Review
	if len(data) > 0 {
		result.Value = data
	}

	return result
}

// GetEnrollmentAgentRights retrieves EnrollmentAgentRights registry value from the remote machine
func (cap *CertAbuseProcessor) GetEnrollmentAgentRights(caName string) builder.RegistryAPIResult {
	result := builder.RegistryAPIResult{}

	regSubKey := fmt.Sprintf("SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\%s", caName)
	regValue := "EnrollmentAgentRights"

	data, err := cap.msrpcObj.GetRegistryKeyData(regSubKey, regValue)
	if err != nil {
		errStr := fmt.Sprint(err)
		result.FailureReason = &errStr
		return result
	}

	result.Collected = true

	if len(data) > 0 {
		//fmt.Fprintf(os.Stderr, "DATA: %v\n", data)
		result.Value = data
	}

	return result
}

// IsUserSpecifiesSanEnabled checks if a requesting user can specify any SAN they want
func (cap *CertAbuseProcessor) IsUserSpecifiesSanEnabled(caName string) builder.BoolRegistryAPIResult {
	result := builder.BoolRegistryAPIResult{}

	regSubKey := fmt.Sprintf("SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\%s\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy", caName)
	regValue := "EditFlags"

	data, err := cap.msrpcObj.GetRegistryKeyData(regSubKey, regValue)
	if err != nil {
		errStr := fmt.Sprint(err)
		result.FailureReason = &errStr
		return result
	}

	result.Collected = true

	if len(data) >= 4 {
		editFlags := binary.LittleEndian.Uint32(data)
		result.Value = (editFlags & 0x00040000) == 0x00040000
	}

	return result
}

// RoleSeparationEnabled checks if role separation is enabled on the CA
func (cap *CertAbuseProcessor) IsRoleSeparationEnabled(caName string) builder.BoolRegistryAPIResult {
	result := builder.BoolRegistryAPIResult{}

	regSubKey := fmt.Sprintf("SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\%s", caName)
	regValue := "RoleSeparationEnabled"

	data, err := cap.msrpcObj.GetRegistryKeyData(regSubKey, regValue)
	if err != nil {
		errStr := fmt.Sprint(err)
		result.FailureReason = &errStr
		return result
	}

	result.Collected = true

	if len(data) >= 4 {
		value := binary.LittleEndian.Uint32(data)
		result.Value = value == 1
	}

	return result
}

// getRegistryPrincipal resolves a SID to a typed principal
func (cap *CertAbuseProcessor) getRegistryPrincipal(
	sidStr string,
	computerDomain string,
	isDomainController bool,
	computerObjectId string,
	machineSid string,
) (builder.TypedPrincipal, bool) {
	if isSidFiltered(sidStr) {
		return builder.TypedPrincipal{}, false
	}

	if isDomainController {
		resolvedPrincipal := builder.ResolveSID(sidStr, computerDomain)
		return resolvedPrincipal, true
	}

	// If the target is not a domain controller,
	// the SID could be well-known / local / domain

	// Handle well-known SIDs by setting their type to LocalGroup/LocalUser
	// and replacing their prefix with the computer's objectSid
	wkp, isWkp := builder.BState().WellKnown.Get(sidStr)
	if isWkp {
		objectType := wkp.Type
		if strings.EqualFold(wkp.Type, "Group") {
			objectType = "LocalGroup"
		} else if strings.EqualFold(wkp.Type, "User") {
			objectType = "LocalUser"
		}

		return builder.TypedPrincipal{
			ObjectIdentifier: computerObjectId + "-" + GetRID(sidStr),
			ObjectType:       objectType,
		}, true
	}

	// Proper local users / groups have SIDs starting with their machine SID
	if machineSid != "" && strings.HasPrefix(sidStr, machineSid+"-") {
		groupRid := GetRID(sidStr)
		newSid := fmt.Sprintf("%s-%s", computerObjectId, groupRid)

		// Type is likely wrongly inferred as LocalGroup, but the original
		// implementation doesn't fix this either
		return builder.TypedPrincipal{
			ObjectIdentifier: newSid,
			ObjectType:       "LocalGroup",
		}, true
	}

	// Otherwise it's likely a domain principal
	return builder.ResolveSIDFromCache(sidStr)
}

// getMachineSid retrieves the machine SID for a computer
func (cap *CertAbuseProcessor) getMachineSid(ctx context.Context, computerName string, computerObjectId string) string {
	// TODO: Check a cache first using computerObjectId

	rpcObj, err := msrpc.NewMSRPC(ctx, computerName, cap.auth)
	defer rpcObj.Close()
	if err != nil {
		//fmt.Fprintf(os.Stderr, "err: %v\n", err)
		return ""
	}

	err = rpcObj.BindSamrClient()
	if err != nil {
		//fmt.Fprintf(os.Stderr, "err: %v\n", err)
		return ""
	}

	resp, err := rpcObj.Client.(samr.SamrClient).Connect(ctx, &samr.ConnectRequest{
		ServerName:    string(computerName),
		DesiredAccess: 0x01 | 0x10 | 0x20,
	})
	if err != nil {
		//fmt.Fprintf(os.Stderr, "err: %v\n", err)
		return ""
	}

	machineSid, err := rpcObj.GetMachineSid(resp.Server, &computerName)
	if err != nil {
		//fmt.Fprintf(os.Stderr, "err: %v\n", err)
		return ""
	}

	// TODO: Cache the machine SID

	return machineSid.String()
}

func (cap *CertAbuseProcessor) isDomainController(computerObjectId string) bool {
	// Iterate over all domains' domain controllers
	for _, dcList := range builder.BState().DomainControllers {
		for _, dcEntry := range dcList {
			if strings.EqualFold(dcEntry.ObjectIdentifier, computerObjectId) {
				return true
			}
		}
	}

	return false
}

// createEnrollmentAgentRestriction creates an enrollment agent restriction from an ACE
func (cap *CertAbuseProcessor) createEnrollmentAgentRestriction(
	aceEntry *ace.AccessControlEntry,
	computerDomain string,
	computerName string,
	isDomainController bool,
	computerObjectId string,
	machineSid string,
) (builder.EnrollmentAgentRestriction, bool) {
	var targets []builder.TypedPrincipal
	index := 0

	agentSid := aceEntry.Identity.SID.String()
	accessType := aceEntry.Header.Type.String()

	agent, success := cap.getRegistryPrincipal(
		agentSid, computerDomain,
		isDomainController, computerObjectId, machineSid,
	)

	if !success {
		return builder.EnrollmentAgentRestriction{}, false
	}

	resultEar := builder.EnrollmentAgentRestriction{
		AccessType: accessType,
		Targets:    targets,
		Agent:      agent,
	}

	// Parse the CALLBACK ACE manually from RawBytes

	// ACE Structure for CALLBACK ACE:
	// Header (4 bytes): Type(1) + Flags(1) + Size(2)
	// Mask (4 bytes): Access mask
	// SID (variable): Principal SID
	// ApplicationData (variable): Callback data

	rawBytes := aceEntry.RawBytes
	if len(rawBytes) < 8 {
		return resultEar, false
	}

	// Skip header (4 bytes) and mask (4 bytes) to get to SID
	offset := 8

	// Parse SID manually to get exact size
	if offset >= len(rawBytes) {
		return resultEar, false
	}

	// SID structure: Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6) + SubAuthorities(4 * count)
	if len(rawBytes) < offset+8 {
		return resultEar, false
	}

	subAuthorityCount := int(rawBytes[offset+1])
	sidSize := 8 + (subAuthorityCount * 4) // 1 + 1 + 6 + (4 * count)

	// ApplicationData starts after header + mask + SID
	applicationDataOffset := offset + sidSize
	if applicationDataOffset >= len(rawBytes) {
		return resultEar, false
	}

	opaque := rawBytes[applicationDataOffset:]
	if len(opaque) < 4 {
		return resultEar, false
	}

	sidCount := binary.LittleEndian.Uint32(opaque[index:])
	index += 4

	// Parse target SIDs
	for i := uint32(0); i < sidCount; i++ {
		if index >= len(opaque) {
			break
		}

		// Manually calculate SID size before unmarshaling
		// SID structure: Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6) + SubAuthorities(4 * count)
		if index+2 > len(opaque) {
			break
		}
		subAuthCount := int(opaque[index+1])
		actualSidSize := 8 + (subAuthCount * 4)

		if index+actualSidSize > len(opaque) {
			break
		}

		parsedSid := &sid.SID{}
		_, err := parsedSid.Unmarshal(opaque[index:])
		if err != nil {
			break
		}

		regPrincipal, success := cap.getRegistryPrincipal(
			parsedSid.String(), computerDomain,
			isDomainController, computerObjectId, machineSid,
		)
		if success {
			resultEar.Targets = append(resultEar.Targets, regPrincipal)
		}

		index += actualSidSize
	}

	resultEar.AllTemplates = index >= len(opaque)

	// Parse template if present
	if index < len(opaque) {
		templateBytes := opaque[index : len(opaque)-2]
		templateRunes := make([]uint16, len(templateBytes)/2)
		for i := 0; i < len(templateRunes); i++ {
			templateRunes[i] = binary.LittleEndian.Uint16(templateBytes[i*2:])
		}
		template := string(utf16.Decode(templateRunes))
		template = strings.ReplaceAll(template, "\u0000", "")

		resolvedTemplate, ok := builder.BState().CertTemplateCache.Get(computerDomain + "+" + template)
		if ok && resolvedTemplate.ObjectIdentifier != "" {
			typedTemplate := resolvedTemplate.ToTypedPrincipal()
			resultEar.Template = &typedTemplate
		}
	}

	return resultEar, true
}
