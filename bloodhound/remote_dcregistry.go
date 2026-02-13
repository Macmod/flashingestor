package bloodhound

import (
	"context"
	"encoding/binary"

	"github.com/Macmod/flashingestor/bloodhound/builder"
)

// collectDCRegistryData retrieves security-relevant registry values from a domain controller
func (rc *RemoteCollector) collectDCRegistryData(ctx context.Context, rpcMgr *RPCManager) builder.DCRegistryData {
	result := builder.DCRegistryData{}

	mrpcObj, err := rpcMgr.GetOrCreateWinregRPC(ctx)
	if err != nil {
		return result
	}

	// Open HKLM once and reuse for all queries
	hiveHandle, err := mrpcObj.OpenLocalMachine()
	if err != nil {
		return result
	}

	// CertificateMappingMethods
	valCMMBytes, err := mrpcObj.QueryRegistryValue(
		hiveHandle,
		"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Schannel",
		"CertificateMappingMethods",
	)

	if err == nil {
		var valCMMInt int
		if len(valCMMBytes) >= 4 {
			valCMMInt = int(binary.LittleEndian.Uint32(valCMMBytes))
		} else {
			valCMMInt = -1
		}

		result.CertificateMappingMethods = &builder.IntRegistryAPIResult{
			APIResult: builder.APIResult{
				Collected:     true,
				FailureReason: nil,
			},
			Value: int(valCMMInt),
		}
	} else {
		errStr := err.Error()
		result.CertificateMappingMethods = &builder.IntRegistryAPIResult{
			APIResult: builder.APIResult{Collected: false, FailureReason: &errStr},
		}
	}

	// StrongCertificateBindingEnforcement
	valSCBEBytes, err := mrpcObj.QueryRegistryValue(
		hiveHandle,
		"SYSTEM\\CurrentControlSet\\Services\\Kdc",
		"StrongCertificateBindingEnforcement",
	)

	if err == nil {
		var valSCBEInt int

		if len(valSCBEBytes) >= 4 {
			valSCBEInt = int(binary.LittleEndian.Uint32(valSCBEBytes))
		} else {
			valSCBEInt = -1
		}

		result.StrongCertificateBindingEnforcement = &builder.IntRegistryAPIResult{
			APIResult: builder.APIResult{
				Collected:     true,
				FailureReason: nil,
			},
			Value: valSCBEInt,
		}
	} else {
		errStr := err.Error()
		result.StrongCertificateBindingEnforcement = &builder.IntRegistryAPIResult{
			APIResult: builder.APIResult{Collected: false, FailureReason: &errStr},
		}
	}

	// VulnerableChannelAllowList
	valVCALBytes, err := mrpcObj.QueryRegistryValue(
		hiveHandle,
		"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
		"VulnerableChannelAllowList",
	)

	if err == nil {
		valVCALStr := string(valVCALBytes)
		result.VulnerableNetlogonSecurityDescriptor = &builder.StrRegistryAPIResult{
			APIResult: builder.APIResult{
				Collected:     true,
				FailureReason: nil,
			},
			Value: valVCALStr,
		}
	} else {
		errStr := err.Error()
		result.VulnerableNetlogonSecurityDescriptor = &builder.StrRegistryAPIResult{
			APIResult: builder.APIResult{Collected: false, FailureReason: &errStr},
		}
	}

	return result
}
