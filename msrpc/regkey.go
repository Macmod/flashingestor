package msrpc

import (
	"fmt"

	"github.com/oiweiwei/go-msrpc/msrpc/rrp/winreg/v1"
)

func (m *MSRPC) GetRegistryKeyData(subkey string, subvalue string) ([]byte, error) {
	client, ok := m.Client.(winreg.WinregClient)
	if !ok {
		return nil, fmt.Errorf("winreg client type assertion failed")
	}

	hklmResp, err := client.OpenLocalMachine(m.Context, &winreg.OpenLocalMachineRequest{
		ServerName:    "",
		DesiredAccess: 0x02000000,
	})

	if err != nil {
		return nil, fmt.Errorf("OpenLocalMachine failed: %w", err)
	}

	hiveHandle := hklmResp.Key
	subkeyResp, err := client.BaseRegOpenKey(m.Context, &winreg.BaseRegOpenKeyRequest{
		Key:           hiveHandle,
		SubKey:        &winreg.UnicodeString{Buffer: subkey},
		Options:       0x00000000,
		DesiredAccess: 0x02000000,
	})

	if err != nil {
		return nil, fmt.Errorf("BaseRegOpenKey failed: %w", err)
	}

	subkeyHandle := subkeyResp.ResultKey
	valueResp, err := client.BaseRegQueryValue(m.Context, &winreg.BaseRegQueryValueRequest{
		Key:        subkeyHandle,
		ValueName:  &winreg.UnicodeString{Buffer: subvalue},
		DataLength: 1024,
	})

	if err != nil {
		return nil, fmt.Errorf("BaseRegQueryValue failed: %w", err)
	}

	return valueResp.Data, nil
}
