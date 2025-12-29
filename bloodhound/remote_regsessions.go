package bloodhound

import (
	"context"
	"fmt"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/msrpc"
)

// collectRegistrySessions retrieves user sessions from the registry ProfileList on a target system
func (rc *RemoteCollector) collectRegistrySessions(ctx context.Context, targetHost string, computerSid string) builder.SessionAPIResult {
	result := builder.SessionAPIResult{
		APIResult: builder.APIResult{Collected: false},
		Results:   []builder.Session{},
	}

	rpcObj, err := msrpc.NewMSRPC(ctx, targetHost, rc.auth)
	if err != nil {
		errStr := fmt.Sprint(err)
		result.FailureReason = &errStr
		return result
	}
	defer rpcObj.Close()

	if err := rpcObj.BindWinregClient(); err != nil {
		errStr := fmt.Sprint(err)
		result.FailureReason = &errStr
		return result
	}

	regSessions, err := rpcObj.GetSessionsFromRegistry(ctx)
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
