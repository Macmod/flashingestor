package bloodhound

import (
	"context"
	"fmt"
	"strings"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/msrpc"
)

// collectPrivilegedSessions retrieves currently logged-on users from a target system via WKSSVC RPC
func (rc *RemoteCollector) collectPrivilegedSessions(ctx context.Context, targetHost string, computerSam string, computerSid string) builder.SessionAPIResult {
	result := builder.SessionAPIResult{
		APIResult: builder.APIResult{Collected: false},
		Results:   []builder.Session{},
	}

	rpcObj, err := msrpc.NewWkssvcRPC(ctx, targetHost, rc.auth)
	if err != nil {
		errStr := fmt.Sprint(err)
		result.FailureReason = &errStr
		return result
	}
	defer rpcObj.Close()

	loggedOn, err := rpcObj.GetLoggedOnUsers(ctx)
	if err != nil {
		errStr := fmt.Sprint(err)
		result.FailureReason = &errStr
		return result
	}

	for _, user := range loggedOn {
		// Ignore empty/malformed/local domains
		if strings.TrimSpace(user.Domain) == "" ||
			strings.Contains(user.Domain, " ") ||
			user.Domain == "." ||
			strings.EqualFold(user.Domain, computerSam) {
			continue
		}

		// Ignore empty usernames and machine accounts
		if strings.TrimSpace(user.Username) == "" ||
			strings.HasSuffix(user.Username, "$") {
			continue
		}

		userObj, ok := builder.BState().SamCache.Get(user.Domain + "+" + user.Username)
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
