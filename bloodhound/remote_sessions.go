package bloodhound

import (
	"context"
	"fmt"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/msrpc"
)

// collectSessions retrieves active network sessions from a target system via SRVSVC RPC
func (rc *RemoteCollector) collectSessions(ctx context.Context, targetHost string, computerSid string, targetDomain string) builder.SessionAPIResult {
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

	if err := rpcObj.BindSrvsvcClient(); err != nil {
		errStr := fmt.Sprint(err)
		result.FailureReason = &errStr
		return result
	}

	sessions, err := rpcObj.GetSessions(ctx)
	if err != nil {
		errStr := fmt.Sprint(err)
		result.FailureReason = &errStr
		return result
	}

	for _, session := range sessions {
		// TODO: Review against:
		// https://github.com/SpecterOps/SharpHoundCommon/blob/1968f8d108be22e52906dd3cd15ddd62cf0544ba/src/CommonLib/Processors/ComputerSessionProcessor.cs#L54
		userObj, ok := builder.BState().SamCache.Get(targetDomain + "+" + session.UserName)
		if !ok {
			continue
		}

		result.Results = append(result.Results, builder.Session{
			ComputerSID: computerSid,
			UserSID:     userObj.ObjectIdentifier,
		})
	}

	result.Collected = true
	return result
}
