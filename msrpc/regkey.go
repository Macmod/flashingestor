package msrpc

import (
	"fmt"

	"github.com/oiweiwei/go-msrpc/msrpc/rrp/winreg/v1"
)

// OpenLocalMachine opens the HKEY_LOCAL_MACHINE hive and returns the handle.
// The caller is responsible for closing this handle when done.
func (m *WinregRPC) OpenLocalMachine() (*winreg.Key, error) {
	hklmResp, err := m.Client.OpenLocalMachine(m.Context, &winreg.OpenLocalMachineRequest{
		ServerName:    "",
		DesiredAccess: 0x02000000,
	})

	if err != nil {
		return nil, fmt.Errorf("OpenLocalMachine failed: %w", err)
	}

	if hklmResp == nil || hklmResp.Key == nil {
		return nil, fmt.Errorf("OpenLocalMachine returned nil key")
	}

	return hklmResp.Key, nil
}

// QueryRegistryValue queries a registry value using an already-opened hive handle.
// This allows reusing the same hive handle for multiple queries without repeated OpenLocalMachine calls.
func (m *WinregRPC) QueryRegistryValue(hiveHandle *winreg.Key, subkey string, subvalue string) ([]byte, error) {
	if hiveHandle == nil {
		return nil, fmt.Errorf("hiveHandle is nil")
	}

	subkeyResp, err := m.Client.BaseRegOpenKey(m.Context, &winreg.BaseRegOpenKeyRequest{
		Key:           hiveHandle,
		SubKey:        &winreg.UnicodeString{Buffer: subkey},
		Options:       0x00000000,
		DesiredAccess: 0x02000000,
	})

	if err != nil {
		return nil, fmt.Errorf("BaseRegOpenKey failed: %w", err)
	}

	if subkeyResp == nil || subkeyResp.ResultKey == nil {
		return nil, fmt.Errorf("BaseRegOpenKey returned nil key")
	}

	subkeyHandle := subkeyResp.ResultKey
	valueResp, err := m.Client.BaseRegQueryValue(m.Context, &winreg.BaseRegQueryValueRequest{
		Key:        subkeyHandle,
		ValueName:  &winreg.UnicodeString{Buffer: subvalue},
		DataLength: 1024,
	})

	if err != nil {
		return nil, fmt.Errorf("BaseRegQueryValue failed: %w", err)
	}

	if valueResp == nil {
		return nil, fmt.Errorf("BaseRegQueryValue returned nil response")
	}

	return valueResp.Data, nil
}

// GetRegistryKeyData is a convenience function that opens HKLM, queries a value, and returns the data.
// For multiple queries, consider using OpenLocalMachine() + QueryRegistryValue() instead to avoid
// repeated OpenLocalMachine calls.
func (m *WinregRPC) GetRegistryKeyData(subkey string, subvalue string) ([]byte, error) {
	hiveHandle, err := m.OpenLocalMachine()
	if err != nil {
		return nil, err
	}

	if hiveHandle == nil {
		return nil, fmt.Errorf("OpenLocalMachine returned nil handle")
	}

	return m.QueryRegistryValue(hiveHandle, subkey, subvalue)
}
