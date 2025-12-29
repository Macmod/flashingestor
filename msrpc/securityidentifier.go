package msrpc

import (
	"fmt"
	"strings"

	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	lsat "github.com/oiweiwei/go-msrpc/msrpc/lsat/lsarpc/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/samr/samr/v1"
)

func (m *MSRPC) GetMachineSid(handle *samr.Handle, testName *string) (*dtyp.SID, error) {
	client, ok := m.Client.(samr.SamrClient)
	if !ok {
		return nil, fmt.Errorf("samr client type assertion failed")
	}

	var sid *dtyp.SID
	if testName == nil {
		return nil, fmt.Errorf("testName cannot be nil")
	}

	result, err := client.LookupDomainInSAMServer(m.Context, &samr.LookupDomainInSAMServerRequest{
		Server: handle,
		Name:   &dtyp.UnicodeString{Buffer: *testName},
	})

	if err == nil {
		sid = result.DomainID
	} else {
		domains, err := m.enumerateDomainsInSAMServer(handle)
		if err != nil {
			return nil, fmt.Errorf("error running EnumerateDomainsInSAMServer: %w", err)
		}

		if len(domains) > 0 {
			targetDomain := domains[0]
			result, err := client.LookupDomainInSAMServer(m.Context, &samr.LookupDomainInSAMServerRequest{
				Server: handle,
				Name:   &dtyp.UnicodeString{Buffer: targetDomain.Name.Buffer},
			})

			if err == nil {
				sid = result.DomainID
			} else {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	return sid, nil
}

type ResolvedSID struct {
	Name      string
	Type      uint16
	Domain    string
	DomainSID string
}

func (m *MSRPC) LookupSids(sids []string) ([]ResolvedSID, error) {
	resolvedSid := make([]ResolvedSID, 0)

	client, ok := m.Client.(lsat.LsarpcClient)
	if !ok {
		return nil, fmt.Errorf("lsat client type assertion failed")
	}

	lsaConResp, err := client.OpenPolicy2(m.Context, &lsat.OpenPolicy2Request{
		// Check mask
		DesiredAccess: dtyp.AccessMaskGenericRead | dtyp.AccessMaskGenericExecute | dtyp.AccessMaskAccessSystemSecurity,
	})

	if err != nil {
		return nil, fmt.Errorf("LsarOpenPolicy2 failed: %w", err)
	}

	handle := lsaConResp.Policy

	sidsToLookup := make([]*lsat.SIDInformation, 0)
	for _, s := range sids {
		sidObj := &SID{}
		err := sidObj.FromString(s)

		if err == nil {
			sidsToLookup = append(sidsToLookup, &lsat.SIDInformation{
				SID: sidObj.SID,
			})
			fmt.Println(sidObj.ToString())
		}
	}

	lookupSidsReq := &lsat.LookupSIDsRequest{
		Policy: handle,
		SIDEnumBuffer: &lsat.SIDEnumBuffer{
			Entries: uint32(len(sidsToLookup)),
			SIDInfo: sidsToLookup,
		},
		TranslatedNames: &lsat.TranslatedNames{
			Entries: 0,
			Names:   nil,
		},
		LookupLevel: 1, // LsapLookupWksta
		MappedCount: 0,
	}

	lookupResp, err := client.LookupSIDs(m.Context, lookupSidsReq)
	if err != nil {
		return nil, fmt.Errorf("LsarLookupSids failed: %w", err)
	}

	for _, name := range lookupResp.TranslatedNames.Names {
		domain := lookupResp.ReferencedDomains.Domains[name.DomainIndex]
		domainNetbios := domain.Name.Buffer
		domainSID := SID{domain.SID}

		resolvedSid = append(resolvedSid, ResolvedSID{
			Name:      name.Name.Buffer,
			Type:      uint16(name.Use),
			Domain:    domainNetbios,
			DomainSID: domainSID.ToString(),
		})
	}

	return resolvedSid, nil
}

type SID struct {
	*dtyp.SID
}

func (s *SID) ToString() string {
	if s == nil || s.SID == nil {
		return "<nil SID>"
	}

	// Defensive: if IDAuthority is nil or shorter than 6 bytes, pad it
	var val []byte
	if s.IDAuthority != nil {
		val = s.IDAuthority.Value[:]
	}
	if len(val) < 6 {
		tmp := make([]byte, 6)
		copy(tmp[6-len(val):], val)
		val = tmp
	}

	// Manual decode of the 6-byte IdentifierAuthority (no Uint64 panic)
	idAuth := uint64(0)
	for i := 0; i < 6; i++ {
		idAuth = (idAuth << 8) | uint64(val[i])
	}

	sidStr := fmt.Sprintf("S-%d-%d", s.Revision, idAuth)

	// Append SubAuthorities
	for _, subAuth := range s.SubAuthority {
		sidStr += fmt.Sprintf("-%d", subAuth)
	}

	return sidStr
}

func (s *SID) FromString(sidStr string) error {
	if !strings.HasPrefix(sidStr, "S-") {
		return fmt.Errorf("invalid SID format: must start with 'S-'")
	}

	parts := strings.Split(sidStr, "-")
	if len(parts) < 3 {
		return fmt.Errorf("invalid SID: too few parts")
	}

	// Parse revision
	var revInt int
	if _, err := fmt.Sscanf(parts[1], "%d", &revInt); err != nil {
		return fmt.Errorf("invalid revision: %w", err)
	}
	revision := uint8(revInt)

	// Parse identifier authority (can be decimal or hex)
	var idAuth uint64
	if strings.HasPrefix(parts[2], "0x") || strings.HasPrefix(parts[2], "0X") {
		_, err := fmt.Sscanf(parts[2], "%x", &idAuth)
		if err != nil {
			return fmt.Errorf("invalid identifier authority: %w", err)
		}
	} else {
		_, err := fmt.Sscanf(parts[2], "%d", &idAuth)
		if err != nil {
			return fmt.Errorf("invalid identifier authority: %w", err)
		}
	}

	// Parse subauthorities
	subAuths := make([]uint32, 0, len(parts)-3)
	for _, p := range parts[3:] {
		var sub uint32
		if _, err := fmt.Sscanf(p, "%d", &sub); err != nil {
			return fmt.Errorf("invalid subauthority %q: %w", p, err)
		}
		subAuths = append(subAuths, sub)
	}

	// Build IdentifierAuthority (6 bytes big-endian)
	idAuthStruct := &dtyp.SIDIDAuthority{
		Value: make([]byte, 6),
	}
	for i := 0; i < 6; i++ {
		idAuthStruct.Value[5-i] = byte(idAuth & 0xFF)
		idAuth >>= 8
	}

	// Construct the SID
	s.SID = &dtyp.SID{
		Revision:          revision,
		SubAuthorityCount: uint8(len(subAuths)),
		IDAuthority:       idAuthStruct,
		SubAuthority:      subAuths,
	}

	return nil
}
