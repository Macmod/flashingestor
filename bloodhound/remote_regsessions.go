package bloodhound

import (
	"context"
	"fmt"

	"github.com/Macmod/flashingestor/bloodhound/builder"
)

// collectRegistrySessions retrieves user sessions from the registry on a target system
func (rc *RemoteCollector) collectRegistrySessions(ctx context.Context, computerSid string, rpcMgr *RPCManager) builder.SessionAPIResult {
	result := builder.SessionAPIResult{
		APIResult: builder.APIResult{Collected: false},
		Results:   []builder.Session{},
	}

	rpcObj, err := rpcMgr.GetOrCreateWinregRPC(ctx)
	if err != nil {
		errStr := fmt.Sprintf("failed to create WinregRPC: %v", err)
		result.FailureReason = &errStr
		return result
	}

	regSessions, err := rpcObj.GetSessionsFromRegistry()
	if err != nil {
		errStr := fmt.Sprint(err)
		result.FailureReason = &errStr
		return result
	}

	for _, userSid := range regSessions {
		result.Results = append(result.Results, builder.Session{
			ComputerSID: computerSid,
			UserSID:     userSid,
		})
	}

	result.Collected = true
	return result
}
