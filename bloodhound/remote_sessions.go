package bloodhound

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/msrpc"
)

// collectSessions retrieves active network sessions from a target system via SRVSVC RPC
func (rc *RemoteCollector) collectSessions(ctx context.Context, targetHost string, computerSid string, targetDomain string) builder.SessionAPIResult {
	result := builder.SessionAPIResult{
		APIResult: builder.APIResult{Collected: false},
		Results:   []builder.Session{},
	}

	rpcObj, err := msrpc.NewSrvsvcRPC(ctx, targetHost, rc.auth)
	if err != nil {
		errStr := fmt.Sprint(err)
		result.FailureReason = &errStr
		return result
	}
	defer rpcObj.Close()

	sessions, err := rpcObj.GetSessions(ctx)
	if err != nil {
		errStr := fmt.Sprint(err)
		result.FailureReason = &errStr
		return result
	}

	for _, session := range sessions {
		userName := session.UserName
		computerSessionName := session.ClientName
		if computerSessionName == "" || userName == "" {
			continue
		}

		currentUser := rc.auth.Creds().Username
		if strings.HasSuffix(userName, "$") || strings.EqualFold(userName, "ANONYMOUS LOGON") || strings.EqualFold(userName, currentUser) {
			continue
		}

		if targetDomain == "." {
			continue
		}

		// Client computer name / IP
		var resolvedComputerSID string
		computerSessionName = strings.TrimPrefix(computerSessionName, "\\\\")

		if computerSessionName == "[::1]" || computerSessionName == "127.0.0.1" {
			resolvedComputerSID = computerSid
		} else {
			if net.ParseIP(computerSessionName) != nil {
				resolver := rc.auth.Resolver()

				// Fall back to DNS reverse lookup
				addrs, err := resolver.LookupAddr(ctx, computerSessionName)
				if err == nil && len(addrs) > 0 {
					// Use the first resolved hostname
					computerSessionName = strings.TrimSuffix(addrs[0], ".")
				}
			}

			realComputerSid, ok := resolveHostname(ctx, rc.auth, computerSessionName, targetDomain)
			if ok {
				resolvedComputerSID = realComputerSid
			}
		}

		if resolvedComputerSID == "" || !strings.HasPrefix(resolvedComputerSID, "S-1") {
			continue
		}

		// Lookup user SID from SAM cache
		// Original SharpHound queries the GC first, but we skip that for now
		userObj, ok := builder.BState().SamCache.Get(targetDomain + "+" + session.UserName)
		if !ok {
			continue
		}

		result.Results = append(result.Results, builder.Session{
			ComputerSID: resolvedComputerSID,
			UserSID:     userObj.ObjectIdentifier,
		})
	}

	result.Collected = true
	return result
}
