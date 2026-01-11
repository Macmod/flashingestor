package bloodhound

import (
	"context"
	"fmt"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/msrpc"
)

// collectSmbInfo retrieves SMB signing information from a target system via RPC
func (rc *RemoteCollector) collectSmbInfo(ctx context.Context, targetHost string) builder.SMBInfoAPIResult {
	result := builder.SMBInfoAPIResult{
		APIResult: builder.APIResult{Collected: false},
		Result:    builder.SMBInfo{},
	}

	rpcObj, err := msrpc.NewWinregRPC(ctx, targetHost, rc.auth)
	if err != nil {
		errStr := fmt.Sprint(err)
		result.FailureReason = &errStr
		return result
	}
	defer rpcObj.Close()

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
