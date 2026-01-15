package bloodhound

import (
	"context"
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/msrpc"
)

// parseRegistryMultiString decodes a REG_MULTI_SZ registry value from UTF-16 LE null-separated byte data
func parseRegistryMultiString(valBytes []byte) []string {
	var strings []string
	if len(valBytes) < 2 {
		return strings
	}

	// Convert UTF-16 LE bytes to UTF-16 code units
	utf16Data := make([]uint16, len(valBytes)/2)
	for i := 0; i < len(utf16Data); i++ {
		utf16Data[i] = binary.LittleEndian.Uint16(valBytes[i*2:])
	}

	// Parse null-separated strings
	start := 0
	for i := 0; i < len(utf16Data); i++ {
		if utf16Data[i] == 0 {
			if i > start {
				// Convert UTF-16 slice to string
				str := string(utf16.Decode(utf16Data[start:i]))
				strings = append(strings, str)
			}
			start = i + 1
		}
	}

	return strings
}

// collectNTLMRegistryData retrieves NTLM authentication configuration from a target system's registry
func (rc *RemoteCollector) collectNTLMRegistryData(ctx context.Context, targetHost string) builder.NTLMRegistryData {
	result := builder.NTLMRegistryData{
		APIResult: builder.APIResult{
			Collected: true,
		},
	}

	mrpcObj, err := msrpc.NewWinregRPC(ctx, targetHost, rc.auth)
	if err != nil {
		errStr := fmt.Sprintf("RPC failure: %v", err)
		result.APIResult.Collected = false
		result.APIResult.FailureReason = &errStr
		return result
	}
	defer mrpcObj.Close()

	// Open HKLM once and reuse for all queries
	hiveHandle, err := mrpcObj.OpenLocalMachine()
	if err != nil {
		errStr := fmt.Sprintf("OpenLocalMachine failed: %v", err)
		result.APIResult.Collected = false
		result.APIResult.FailureReason = &errStr
		return result
	}

	// ClientAllowedNTLMServers - REG_MULTI_SZ
	valBytes, err := mrpcObj.QueryRegistryValue(
		hiveHandle,
		"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
		"ClientAllowedNTLMServers",
	)
	if err == nil {
		result.Result.ClientAllowedNTLMServers = parseRegistryMultiString(valBytes)
	} else {
		/*
			No error handling currently
			errStr := fmt.Sprintf("QueryRegistryValue failed: %v", err)
		*/
	}

	// NtlmMinClientSec - REG_DWORD
	valBytes, err = mrpcObj.QueryRegistryValue(
		hiveHandle,
		"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
		"NtlmMinClientSec",
	)
	if err == nil {
		if len(valBytes) >= 4 {
			valInt := binary.LittleEndian.Uint32(valBytes)
			result.Result.NtlmMinClientSec = &valInt
		}
	} else {
		/*
			No error handling currently
			errStr := fmt.Sprintf("QueryRegistryValue failed: %v", err)
		*/
	}

	// NtlmMinServerSec - REG_DWORD
	valBytes, err = mrpcObj.QueryRegistryValue(
		hiveHandle,
		"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
		"NtlmMinServerSec",
	)
	if err == nil {
		if len(valBytes) >= 4 {
			valInt := binary.LittleEndian.Uint32(valBytes)
			result.Result.NtlmMinServerSec = &valInt
		}
	} else {
		/*
			No error handling currently
			errStr := fmt.Sprintf("QueryRegistryValue failed: %v", err)
		*/
	}

	// RestrictReceivingNTLMTraffic - REG_DWORD
	valBytes, err = mrpcObj.QueryRegistryValue(
		hiveHandle,
		"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
		"RestrictReceivingNTLMTraffic",
	)
	if err == nil {
		if len(valBytes) >= 4 {
			valInt := binary.LittleEndian.Uint32(valBytes)
			result.Result.RestrictReceivingNtlmTraffic = &valInt
		}
	} else {
		/*
			No error handling currently
			errStr := fmt.Sprintf("QueryRegistryValue failed: %v", err)
		*/
	}

	// RestrictSendingNTLMTraffic - REG_DWORD
	valBytes, err = mrpcObj.QueryRegistryValue(
		hiveHandle,
		"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
		"RestrictSendingNTLMTraffic",
	)
	if err == nil {
		if len(valBytes) >= 4 {
			valInt := binary.LittleEndian.Uint32(valBytes)
			result.Result.RestrictSendingNtlmTraffic = &valInt
		}
	} else {
		/*
			No error handling currently
			errStr := fmt.Sprintf("QueryRegistryValue failed: %v", err)
		*/
	}

	// LMCompatibilityLevel - REG_DWORD
	valBytes, err = mrpcObj.QueryRegistryValue(
		hiveHandle,
		"SYSTEM\\CurrentControlSet\\Control\\Lsa",
		"LMCompatibilityLevel",
	)
	if err == nil {
		if len(valBytes) >= 4 {
			valInt := binary.LittleEndian.Uint32(valBytes)
			result.Result.LmCompatibilityLevel = &valInt
		}
	} else {
		/*
			No error handling currently
			errStr := fmt.Sprintf("QueryRegistryValue failed: %v", err)
		*/
	}

	// UseMachineId - REG_DWORD
	valBytes, err = mrpcObj.QueryRegistryValue(
		hiveHandle,
		"SYSTEM\\CurrentControlSet\\Control\\Lsa",
		"UseMachineId",
	)
	if err == nil {
		if len(valBytes) >= 4 {
			valInt := binary.LittleEndian.Uint32(valBytes)
			result.Result.UseMachineId = &valInt
		}
	} else {
		/*
			No error handling currently
			errStr := fmt.Sprintf("QueryRegistryValue failed: %v", err)
		*/
	}

	// EnableSecuritySignature - REG_DWORD
	valBytes, err = mrpcObj.QueryRegistryValue(
		hiveHandle,
		"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
		"EnableSecuritySignature",
	)
	if err == nil {
		if len(valBytes) >= 4 {
			valInt := binary.LittleEndian.Uint32(valBytes)
			result.Result.EnableSecuritySignature = &valInt
		}
	} else {
		/*
			No error handling currently
			errStr := fmt.Sprintf("QueryRegistryValue failed: %v", err)
		*/
	}

	// RequireSecuritySignature - REG_DWORD
	valBytes, err = mrpcObj.QueryRegistryValue(
		hiveHandle,
		"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
		"RequireSecuritySignature",
	)
	if err == nil {
		if len(valBytes) >= 4 {
			valInt := binary.LittleEndian.Uint32(valBytes)
			result.Result.RequireSecuritySignature = &valInt
		}
	} else {
		/*
			No error handling currently
			errStr := fmt.Sprintf("QueryRegistryValue failed: %v", err)
		*/
	}

	return result
}
