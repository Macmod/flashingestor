package bloodhound

import (
	"context"
	"fmt"
	"strings"

	"github.com/Macmod/flashingestor/bloodhound/builder"
)

// collectPrivilegedSessions retrieves currently logged-on users from a target system via WKSSVC RPC
func (rc *RemoteCollector) collectPrivilegedSessions(ctx context.Context, computerSam string, computerSid string, rpcMgr *RPCManager) builder.SessionAPIResult {
	result := builder.SessionAPIResult{
		APIResult: builder.APIResult{Collected: false},
		Results:   []builder.Session{},
	}

	rpcObj, err := rpcMgr.GetOrCreateWkssvcRPC(ctx)
	if err != nil {
		errStr := fmt.Sprint(err)
		result.FailureReason = &errStr
		return result
	}

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

		domain := user.Domain
		if resolvedDomain, ok := builder.BState().NetBIOSDomainCache.Get(domain); ok && resolvedDomain != "" {
			domain = resolvedDomain
		}

		// Ignore empty usernames and machine accounts
		if strings.TrimSpace(user.Username) == "" ||
			strings.HasSuffix(user.Username, "$") {
			continue
		}

		userObj, ok := builder.BState().SamCache.Get(domain + "+" + user.Username)
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
