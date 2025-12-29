package msrpc

import (
	"errors"
	"fmt"

	"github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
	"github.com/oiweiwei/go-msrpc/msrpc/samr/samr/v1"
)

// enumerateDomainsInSAMServer enumerates all domains with pagination
func (m *MSRPC) enumerateDomainsInSAMServer(handle *samr.Handle) ([]*samr.RIDEnumeration, error) {
	client, ok := m.Client.(samr.SamrClient)
	if !ok {
		return nil, fmt.Errorf("samr client type assertion failed")
	}

	var domains []*samr.RIDEnumeration

	for enum := uint32(0); ; {
		resp, err := client.EnumerateDomainsInSAMServer(m.Context, &samr.EnumerateDomainsInSAMServerRequest{
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
func (m *MSRPC) enumerateAliasesInDomain(client samr.SamrClient, handle *samr.Handle) ([]*samr.RIDEnumeration, error) {
	var aliases []*samr.RIDEnumeration

	for enum := uint32(0); ; {
		resp, err := client.EnumerateAliasesInDomain(m.Context, &samr.EnumerateAliasesInDomainRequest{
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
