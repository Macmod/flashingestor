package bloodhound

import (
	"context"
	"fmt"

	"github.com/Macmod/flashingestor/bloodhound/builder"
)

// collectSmbInfo retrieves SMB signing information from a target system via RPC
func (rc *RemoteCollector) collectSmbInfo(ctx context.Context, rpcMgr *RPCManager) builder.SMBInfoAPIResult {
	result := builder.SMBInfoAPIResult{
		APIResult: builder.APIResult{Collected: false},
		Result:    builder.SMBInfo{},
	}

	rpcObj, err := rpcMgr.GetOrCreateWinregRPC(ctx)
	if err != nil {
		errStr := fmt.Sprintf("failed to create WinregRPC: %v", err)
		result.FailureReason = &errStr
		return result
	}

	isSigningRequired, determined, err := rpcObj.GetRegistrySigningRequired()
	if err != nil {
		errStr := fmt.Sprint(err)
		result.FailureReason = &errStr
		return result
	}

	result.Collected = determined
	result.Result.SigningEnabled = determined && isSigningRequired

	// TODO: Actively check for signing by negotiating a session via SMB1 / SMB2
	//       and checking for errors in the response

	return result
}
