package msrpc

import (
	"encoding/binary"
	"fmt"
)

// GetRegistrySigningRequired determines SMB signing requirements from registry values.
// It follows the logic from SharpHound's CheckRegistrySigningRequired method.
// Returns: (signingRequired bool, determined bool, error)
// - signingRequired: whether SMB signing is required
// - determined: whether we could determine the result conclusively
// - error: any error that occurred
func (m *WinregRPC) GetRegistrySigningRequired() (bool, bool, error) {
	const keyPath = `SYSTEM\CurrentControlSet\Services\LanManServer\Parameters`
	const requireValueName = "RequireSecuritySignature"
	const enableValueName = "EnableSecuritySignature"

	// Try to get RequireSecuritySignature
	requireBytes, requireErr := m.GetRegistryKeyData(keyPath, requireValueName)

	// If RequireSecuritySignature exists, use its value
	if requireErr == nil && len(requireBytes) >= 4 {
		required := binary.LittleEndian.Uint32(requireBytes) != 0
		return required, true, nil
	}

	// RequireSecuritySignature doesn't exist, check EnableSecuritySignature
	enableBytes, enableErr := m.GetRegistryKeyData(keyPath, enableValueName)

	if enableErr == nil && len(enableBytes) >= 4 {
		enabled := binary.LittleEndian.Uint32(enableBytes) != 0

		// If EnableSecuritySignature is False (0), we know signing is NOT required
		if !enabled {
			return false, true, nil
		}

		// EnableSecuritySignature is True (non-zero), but we can't conclude anything
		// because RequireSecuritySignature is missing
		return false, false, fmt.Errorf("could not acquire enough registries to determine SMB signing info")
	}

	// Both registry values are missing or unreadable
	return false, false, fmt.Errorf("registry checks failed:\n%v\n%v", requireErr, enableErr)
}
