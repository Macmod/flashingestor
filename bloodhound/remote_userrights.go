package bloodhound

import (
	"context"
	"fmt"
	"strings"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/msrpc"
	lsat "github.com/oiweiwei/go-msrpc/msrpc/lsat/lsarpc/v0"
)

// GetRID extracts the Relative Identifier (final component) from a SID string
func GetRID(sid string) string {
	parts := strings.Split(sid, "-")
	return parts[len(parts)-1]
}

// collectUserRights retrieves user rights assignments from a target system via LSA RPC
func (rc *RemoteCollector) collectUserRights(ctx context.Context, targetIp string, targetHost string, computerObjectId string, isDC bool, domain string) []builder.UserRightsAPIResult {
	rpcObj, err := msrpc.NewLsadRPC(ctx, targetIp, rc.auth)

	if err != nil {
		errStr := fmt.Sprint(err)
		result := builder.UserRightsAPIResult{
			APIResult: builder.APIResult{Collected: false, FailureReason: &errStr},
		}
		return []builder.UserRightsAPIResult{result}
	}

	defer rpcObj.Close()

	desiredPrivileges := []string{
		"SeRemoteInteractiveLogonRight",
	}

	userRights, err := rpcObj.GetUserRightsAssignments(desiredPrivileges)
	if err != nil {
		errStr := fmt.Sprint(err)
		result := builder.UserRightsAPIResult{
			APIResult: builder.APIResult{Collected: false, FailureReason: &errStr},
		}
		return []builder.UserRightsAPIResult{result}
	}

	machineSid, _ := builder.GetMachineSID(ctx, rc.auth, targetIp, computerObjectId)

	results := []builder.UserRightsAPIResult{}

	for privilege, principals := range userRights {
		result := builder.UserRightsAPIResult{
			APIResult: builder.APIResult{
				Collected: true,
			},
			Privilege:  privilege,
			Results:    []builder.TypedPrincipal{},
			LocalNames: []builder.NamedPrincipal{},
		}

		for _, principalSid := range principals {
			// Is this the right check?
			if isSidFiltered(principalSid) {
				continue
			}

			if isDC {
				/* Is this really needed? */
				// TODO: review resolution logic
				resolvedPrincipal := builder.ResolveSID(principalSid, domain)
				result.Results = append(result.Results, resolvedPrincipal)
				continue
			}

			wkp, isWkp := builder.BState().WellKnown.Get(principalSid)
			if isWkp {
				if principalSid == "S-1-1-0" || principalSid == "S-1-5-11" {
					// Handle Everyone / Authenticated Users
					result.Results = append(result.Results, builder.ResolveSID(principalSid, domain))
				} else {
					// Handle other well-known SIDs
					objectType := wkp.Type
					if strings.EqualFold(wkp.Type, "Group") {
						objectType = "LocalGroup"
					} else if strings.EqualFold(wkp.Type, "User") {
						objectType = "LocalUser"
					}

					result.Results = append(result.Results, builder.TypedPrincipal{
						ObjectIdentifier: computerObjectId + "-" + GetRID(principalSid),
						ObjectType:       objectType,
					})
				}
				continue
			}

			if machineSid != "" && strings.HasPrefix(principalSid, machineSid+"-") {
				newSid := fmt.Sprintf("%s-%s", machineSid, GetRID(principalSid))

				// Need LsatRPC for SID lookup
				lsatObj, err := msrpc.NewLsatRPC(ctx, targetIp, rc.auth)
				if err != nil {
					continue
				}
				defer lsatObj.Close()

				resolvedSids, err := lsatObj.LookupSids([]string{principalSid})
				if err != nil || len(resolvedSids) != 1 {
					//fmt.Fprintf(os.Stderr, "Failed to lookup SID %s: %v\n", principalSid, err)
					continue
				}

				namedPrincipal := builder.NamedPrincipal{
					ObjectIdentifier: newSid,
					PrincipalName:    fmt.Sprintf("%s@%s", strings.ToUpper(resolvedSids[0].Name), strings.ToUpper(targetHost)),
				}

				objectType := "Base"
				if resolvedSids[0].Type == uint16(lsat.SIDNameUseTypeUser) {
					objectType = "LocalUser"
				} else if resolvedSids[0].Type == uint16(lsat.SIDNameUseTypeGroup) ||
					resolvedSids[0].Type == uint16(lsat.SIDNameUseTypeAlias) {
					objectType = "LocalGroup"
				}

				if objectType == "LocalUser" {
					// Throw out local users - I'm not sure why, but SharpHound skips these
					// in UserRightsAssignmentProcessor.cs
					continue
				}

				resolvedPrincipal := builder.TypedPrincipal{
					ObjectIdentifier: newSid,
					ObjectType:       objectType,
				}

				result.Results = append(result.Results, resolvedPrincipal)
				result.LocalNames = append(result.LocalNames, namedPrincipal)
				continue
			}

			// Otherwise, it's a domain principal in a local group
			resolvedPrincipal, ok := builder.ResolveSIDFromCache(principalSid)
			if ok {
				result.Results = append(result.Results, resolvedPrincipal)
			}
		}

		results = append(results, result)
	}

	return results
}
