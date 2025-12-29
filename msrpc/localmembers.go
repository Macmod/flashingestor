package msrpc

import (
	"fmt"
	"strings"

	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"github.com/oiweiwei/go-msrpc/msrpc/samr/samr/v1"
)

type GroupAlias struct {
	RelativeID uint32
	Name       string
	Domain     string
	Members    []string
}

func (m *MSRPC) GetLocalGroupMembers(isDC bool) ([]GroupAlias, error) {
	client, ok := m.Client.(samr.SamrClient)
	if !ok {
		return nil, fmt.Errorf("samr client type assertion failed")
	}

	groupAliases := make([]GroupAlias, 0)

	samrConResp, err := client.Connect(m.Context, &samr.ConnectRequest{
		DesiredAccess: dtyp.AccessMaskGenericRead | dtyp.AccessMaskGenericExecute | dtyp.AccessMaskAccessSystemSecurity,
	})

	if err != nil {
		return nil, fmt.Errorf("SamrConnect failed: %w", err)
	}

	handle := samrConResp.Server

	// TODO: Pagination?
	domsResp, err := client.EnumerateDomainsInSAMServer(m.Context, &samr.EnumerateDomainsInSAMServerRequest{
		Server:                 handle,
		EnumerationContext:     0,
		PreferredMaximumLength: 0xFFFFFFFF,
	})

	if err != nil {
		return nil, fmt.Errorf("x EnumerateDomainsInSAMServer failed: %w", err)
	}

	for _, domain := range domsResp.Buffer.Buffer {
		if isDC && !strings.EqualFold(domain.Name.Buffer, "Builtin") {
			continue
		}

		lookupResp, err := client.LookupDomainInSAMServer(m.Context, &samr.LookupDomainInSAMServerRequest{
			Server: handle,
			Name:   domain.Name,
		})
		if err != nil {
			return nil, fmt.Errorf("LookupDomainInSAMServer failed: %w", err)
		}

		domainResp, err := client.OpenDomain(m.Context, &samr.OpenDomainRequest{
			Server:        handle,
			DomainID:      lookupResp.DomainID,
			DesiredAccess: 0x00000200 | dtyp.AccessMaskMaximumAllowed,
		})
		if err != nil {
			return nil, fmt.Errorf("SamrOpenDomain failed: %w", err)
		}

		// TODO: Pagination?
		aliasesResp, err := client.EnumerateAliasesInDomain(m.Context, &samr.EnumerateAliasesInDomainRequest{
			Domain:             domainResp.Domain,
			EnumerationContext: 0,
		})
		if err != nil {
			return nil, fmt.Errorf("SamrEnumerateAliasesInDomain failed: %w", err)
		}

		for _, alias := range aliasesResp.Buffer.Buffer {
			localGroupMembers := make([]string, 0)

			aliasResp, err := client.OpenAlias(m.Context, &samr.OpenAliasRequest{
				Domain:        domainResp.Domain,
				DesiredAccess: dtyp.AccessMaskGenericRead | dtyp.AccessMaskMaximumAllowed,
				AliasID:       alias.RelativeID,
			})
			if err != nil {
				return nil, fmt.Errorf("SamrOpenAlias failed: %w", err)
			}

			membersResp, err := client.GetMembersInAlias(m.Context, &samr.GetMembersInAliasRequest{
				AliasHandle: aliasResp.AliasHandle,
			})
			if err != nil {
				return nil, fmt.Errorf("SamrGetMembersInAlias failed: %w", err)
			}

			for _, member := range membersResp.Members.SIDs {
				memberSid := SID{member.SIDPointer}
				localGroupMembers = append(localGroupMembers, memberSid.String())
			}

			groupAliases = append(groupAliases, GroupAlias{
				RelativeID: alias.RelativeID,
				Name:       alias.Name.Buffer,
				Domain:     domain.Name.Buffer,
				Members:    localGroupMembers,
			})
		}
	}

	return groupAliases, nil
}
