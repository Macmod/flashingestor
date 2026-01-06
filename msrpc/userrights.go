package msrpc

import (
	"fmt"

	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	lsad "github.com/oiweiwei/go-msrpc/msrpc/lsad/lsarpc/v0"
)

func (m *LsadRPC) GetUserRightsAssignments(privileges []string) (map[string][]string, error) {
	results := make(map[string][]string)

	// Open LSA Policy
	lsaConResp, err := m.Client.OpenPolicy2(m.Context, &lsad.OpenPolicy2Request{
		DesiredAccess: dtyp.AccessMaskGenericRead | dtyp.AccessMaskGenericExecute,
	})
	if err != nil {
		return nil, fmt.Errorf("LsarOpenPolicy2 failed: %w", err)
	}

	handle := lsaConResp.Policy

	// Enumerate accounts for each privilege
	for _, privilege := range privileges {
		// Enumerate accounts with this privilege
		enumResp, err := m.Client.EnumerateAccountsWithUserRight(m.Context, &lsad.EnumerateAccountsWithUserRightRequest{
			Policy:    handle,
			UserRight: &dtyp.UnicodeString{Buffer: privilege},
		})

		if err != nil {
			// If privilege doesn't exist or no accounts have it, skip
			continue
		}

		if enumResp.EnumerationBuffer == nil || enumResp.EnumerationBuffer.EntriesRead == 0 {
			continue
		}

		// Convert SIDs to strings
		principals := make([]string, 0, enumResp.EnumerationBuffer.EntriesRead)
		for _, accountInfo := range enumResp.EnumerationBuffer.Information {
			if accountInfo.SID != nil {
				sidObj := &SID{SID: accountInfo.SID}
				principals = append(principals, sidObj.ToString())
			}
		}

		results[privilege] = principals
	}

	return results, nil
}
