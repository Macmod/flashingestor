package bloodhound

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/msrpc"
)

// collectDCRegistryData retrieves security-relevant registry values from a domain controller
func (rc *RemoteCollector) collectDCRegistryData(ctx context.Context, targetHost string) builder.DCRegistryData {
	result := builder.DCRegistryData{}

	mrpcObj, err := msrpc.NewWinregRPC(ctx, targetHost, rc.auth)
	if err != nil {
		return result
	}
	defer mrpcObj.Close()

	// CertificateMappingMethods
	valCMMBytes, err := mrpcObj.GetRegistryKeyData(
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
		errStr := fmt.Sprintf("Get CertificateMappingMethods failed: %v", err)
		result.CertificateMappingMethods = &builder.IntRegistryAPIResult{
			APIResult: builder.APIResult{Collected: false, FailureReason: &errStr},
		}
	}

	// StrongCertificateBindingEnforcement
	valSCBEBytes, err := mrpcObj.GetRegistryKeyData(
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
		errStr := fmt.Sprintf("Get StrongCertificateBindingEnforcement failed: %v", err)
		result.StrongCertificateBindingEnforcement = &builder.IntRegistryAPIResult{
			APIResult: builder.APIResult{Collected: false, FailureReason: &errStr},
		}
	}

	// VulnerableChannelAllowList
	valVCALBytes, err := mrpcObj.GetRegistryKeyData(
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
		errStr := fmt.Sprintf("Get VulnerableChannelAllowList failed: %v", err)
		result.VulnerableNetlogonSecurityDescriptor = &builder.StrRegistryAPIResult{
			APIResult: builder.APIResult{Collected: false, FailureReason: &errStr},
		}
	}

	return result
}
