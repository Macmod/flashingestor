package bloodhound

import (
	"context"
	"fmt"
	"strings"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/msrpc"
	lsat "github.com/oiweiwei/go-msrpc/msrpc/lsat/lsarpc/v0"
)

// collectLocalGroups retrieves local group memberships from a target system via RPC
func (rc *RemoteCollector) collectLocalGroups(ctx context.Context, targetIp string, targetHost string, computerSid string, isDC bool, domain string) []builder.LocalGroupAPIResult {
	localGroupResults := []builder.LocalGroupAPIResult{}
	rpcObj, err := msrpc.NewMSRPC(ctx, targetIp, rc.auth)
	if err != nil {
		return localGroupResults
	}
	defer rpcObj.Close()

	if err := rpcObj.BindSamrClient(); err != nil {
		return localGroupResults
	}

	localGroups, err := rpcObj.GetLocalGroupMembers(isDC)
	for _, localGroup := range localGroups {
		groupRid := localGroup.RelativeID
		groupResult := builder.LocalGroupAPIResult{}

		if isDC && strings.EqualFold(localGroup.Domain, "Builtin") {
			builtinGroupSid := "S-1-5-32-" + fmt.Sprint(groupRid)
			groupWkp, ok := builder.BState().WellKnown.Get(builtinGroupSid)
			if ok {
				groupResult.ObjectIdentifier = fmt.Sprintf("%s-S-1-5-32-%d", domain, groupRid)
				groupResult.Name = groupWkp.Name
			}
		} else {
			groupResult.ObjectIdentifier = fmt.Sprintf("%s-%d", computerSid, groupRid)
			groupResult.Name = strings.ToUpper(localGroup.Name + "@" + targetHost)
		}

		collected := false
		failureReason := ""
		var results []builder.TypedPrincipal
		var names []builder.NamedPrincipal

		if err == nil {
			results, names = rc.ProcessLocalGroupMembers(ctx, localGroup.Members, computerSid, targetHost, isDC, domain)
			collected = true
		} else {
			failureReason = fmt.Sprint(err)
		}

		groupResult.APIResult = builder.APIResult{
			Collected:     collected,
			FailureReason: &failureReason,
		}

		groupResult.Results = results
		groupResult.LocalNames = names

		localGroupResults = append(localGroupResults, groupResult)
	}

	return localGroupResults
}

// Helpers
func (rc *RemoteCollector) ProcessLocalGroupMembers(ctx context.Context, localMembers []string, machineSid string, machineHost string, isDC bool, domain string) ([]builder.TypedPrincipal, []builder.NamedPrincipal) {
	results := []builder.TypedPrincipal{}
	names := []builder.NamedPrincipal{}

	for _, memberSid := range localMembers {
		if isSidFiltered(memberSid) {
			continue
		}

		if isDC {
			/* Is this really needed? */
			// TODO: review resolution logic
			resolvedPrincipal := builder.ResolveSID(memberSid, domain)
			results = append(results, resolvedPrincipal)
			continue
		}

		wkp, isWkp := builder.BState().WellKnown.Get(memberSid)
		if isWkp {
			if memberSid == "S-1-1-0" || memberSid == "S-1-5-11" {
				// Handle Everyone / Authenticated Users
				results = append(results, builder.ResolveSID(memberSid, domain))
			} else {
				// Handle other well-known SIDs
				objectType := wkp.Type
				if strings.EqualFold(wkp.Type, "Group") {
					objectType = "LocalGroup"
				} else if strings.EqualFold(wkp.Type, "User") {
					objectType = "LocalUser"
				}

				results = append(results, builder.TypedPrincipal{
					ObjectIdentifier: machineSid + "-" + GetRID(memberSid),
					ObjectType:       objectType,
				})
			}
			continue
		}

		// If the security identifier starts with the machine sid, we need to resolve it as a local object
		if strings.HasPrefix(memberSid, machineSid+"-") {
			newSid := fmt.Sprintf("%s-%s", machineSid, GetRID(memberSid))

			rpcObj, err := msrpc.NewMSRPC(ctx, machineHost, rc.auth)
			if err != nil {
				continue
			}
			defer rpcObj.Close()

			if err := rpcObj.BindLsatClient(); err != nil {
				continue
			}

			resolvedSids, err := rpcObj.LookupSids([]string{memberSid})
			if err != nil || len(resolvedSids) != 1 {
				// TODO: Review
				continue
			}

			namedPrincipal := builder.NamedPrincipal{
				ObjectIdentifier: newSid,
				PrincipalName:    fmt.Sprintf("%s@%s", strings.ToUpper(resolvedSids[0].Name), strings.ToUpper(machineHost)),
			}

			objectType := "Base"
			if resolvedSids[0].Type == uint16(lsat.SIDNameUseTypeUser) {
				objectType = "LocalUser"
			} else if resolvedSids[0].Type == uint16(lsat.SIDNameUseTypeGroup) ||
				resolvedSids[0].Type == uint16(lsat.SIDNameUseTypeAlias) {
				objectType = "LocalGroup"
			}

			if objectType == "LocalUser" {
				// Throw out local users
				continue
			}

			resolvedPrincipal := builder.TypedPrincipal{
				ObjectIdentifier: newSid,
				ObjectType:       objectType,
			}

			results = append(results, resolvedPrincipal)
			names = append(names, namedPrincipal)
			continue
		}

		// Otherwise, it's a domain principal in a local group
		// TODO: Review resolution logic
		resolvedPrincipal, ok := builder.ResolveSIDFromCache(memberSid)
		if ok {
			results = append(results, resolvedPrincipal)
		}
	}

	return results, names
}
