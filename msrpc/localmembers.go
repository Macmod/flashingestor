package msrpc

import (
	"errors"
	"fmt"
	"strings"

	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
	"github.com/oiweiwei/go-msrpc/msrpc/samr/samr/v1"
)

type GroupAlias struct {
	RelativeID uint32
	Name       string
	Domain     string
	Members    []string
}

func (m *SamrRPC) GetLocalGroupMembers(isDC bool) ([]GroupAlias, error) {
	groupAliases := make([]GroupAlias, 0)

	samrConResp, err := m.Client.Connect(m.Context, &samr.ConnectRequest{
		DesiredAccess: dtyp.AccessMaskGenericRead | dtyp.AccessMaskGenericExecute | dtyp.AccessMaskAccessSystemSecurity,
	})

	if err != nil {
		return nil, fmt.Errorf("SamrConnect failed: %w", err)
	}

	handle := samrConResp.Server

	domains, err := m.enumerateDomainsInSAMServer(handle)
	if err != nil {
		return nil, fmt.Errorf("EnumerateDomainsInSAMServer failed: %w", err)
	}

	for _, domain := range domains {
		if isDC && !strings.EqualFold(domain.Name.Buffer, "Builtin") {
			continue
		}

		lookupResp, err := m.Client.LookupDomainInSAMServer(m.Context, &samr.LookupDomainInSAMServerRequest{
			Server: handle,
			Name:   domain.Name,
		})
		if err != nil {
			//return nil, fmt.Errorf("LookupDomainInSAMServer failed: %w", err)
			continue
		}

		domainResp, err := m.Client.OpenDomain(m.Context, &samr.OpenDomainRequest{
			Server:        handle,
			DomainID:      lookupResp.DomainID,
			DesiredAccess: 0x00000200 | dtyp.AccessMaskMaximumAllowed,
		})
		if err != nil {
			//return nil, fmt.Errorf("SamrOpenDomain failed: %w", err)
			continue
		}

		aliases, err := m.enumerateAliasesInDomain(domainResp.Domain)
		if err != nil {
			//return nil, fmt.Errorf("EnumerateAliasesInDomain failed: %w", err)
			continue
		}

		for _, alias := range aliases {
			localGroupMembers := make([]string, 0)

			aliasResp, err := m.Client.OpenAlias(m.Context, &samr.OpenAliasRequest{
				Domain:        domainResp.Domain,
				DesiredAccess: dtyp.AccessMaskGenericRead | dtyp.AccessMaskMaximumAllowed,
				AliasID:       alias.RelativeID,
			})
			if err != nil {
				//return nil, fmt.Errorf("SamrOpenAlias failed: %w", err)
				continue
			}

			membersResp, err := m.Client.GetMembersInAlias(m.Context, &samr.GetMembersInAliasRequest{
				AliasHandle: aliasResp.AliasHandle,
			})
			if err != nil || membersResp == nil || membersResp.Members == nil {
				//return nil, fmt.Errorf("SamrGetMembersInAlias failed: %w", err)
				continue
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

// enumerateDomainsInSAMServer enumerates all domains with pagination
func (m *SamrRPC) enumerateDomainsInSAMServer(handle *samr.Handle) ([]*samr.RIDEnumeration, error) {
	var domains []*samr.RIDEnumeration

	for enum := uint32(0); ; {
		resp, err := m.Client.EnumerateDomainsInSAMServer(m.Context, &samr.EnumerateDomainsInSAMServerRequest{
			Server:             handle,
			EnumerationContext: enum,
		})
		if err != nil {
			if !errors.Is(err, ntstatus.StatusMoreEntries) {
				return nil, err
			}
		}

		domains = append(domains, resp.Buffer.Buffer...)

		if enum = resp.EnumerationContext; resp.CountReturned == 0 || enum == 0 {
			break
		}
	}

	return domains, nil
}

// enumerateAliasesInDomain enumerates all aliases in a domain with pagination
func (m *SamrRPC) enumerateAliasesInDomain(handle *samr.Handle) ([]*samr.RIDEnumeration, error) {
	var aliases []*samr.RIDEnumeration

	for enum := uint32(0); ; {
		resp, err := m.Client.EnumerateAliasesInDomain(m.Context, &samr.EnumerateAliasesInDomainRequest{
			Domain:             handle,
			EnumerationContext: enum,
		})
		if err != nil {
			if !errors.Is(err, ntstatus.StatusMoreEntries) {
				return nil, err
			}
		}

		aliases = append(aliases, resp.Buffer.Buffer...)

		if enum = resp.EnumerationContext; resp.CountReturned == 0 || enum == 0 {
			break
		}
	}

	return aliases, nil
}
