package msrpc

import (
	"fmt"

	"github.com/oiweiwei/go-msrpc/msrpc/rrp/winreg/v1"
)

func (m *WinregRPC) GetRegistryKeyData(subkey string, subvalue string) ([]byte, error) {
	hklmResp, err := m.Client.OpenLocalMachine(m.Context, &winreg.OpenLocalMachineRequest{
		ServerName:    "",
		DesiredAccess: 0x02000000,
	})

	if err != nil {
		return nil, fmt.Errorf("OpenLocalMachine failed: %w", err)
	}

	hiveHandle := hklmResp.Key
	subkeyResp, err := m.Client.BaseRegOpenKey(m.Context, &winreg.BaseRegOpenKeyRequest{
		Key:           hiveHandle,
		SubKey:        &winreg.UnicodeString{Buffer: subkey},
		Options:       0x00000000,
		DesiredAccess: 0x02000000,
	})

	if err != nil {
		return nil, fmt.Errorf("BaseRegOpenKey failed: %w", err)
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

	return valueResp.Data, nil
}
