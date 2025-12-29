package msrpc

import (
	"context"
	"fmt"
	"regexp"

	"github.com/oiweiwei/go-msrpc/msrpc/rrp/winreg/v1"
)

func (m *MSRPC) GetSessionsFromRegistry(ctx context.Context) ([]string, error) {
	sids := make([]string, 0)

	client, ok := m.Client.(winreg.WinregClient)
	if !ok {
		return nil, fmt.Errorf("winreg client type assertion failed")
	}

	openUsersResp, err := client.OpenUsers(m.Context, &winreg.OpenUsersRequest{
		DesiredAccess: winreg.KeyEnumerateSubKeys,
	})

	if err != nil {
		return nil, fmt.Errorf("OpenUsers failed: %w", err)
	}

	var resp *winreg.BaseRegEnumKeyResponse
	for index := uint32(0); err == nil; index++ {
		resp, err = client.BaseRegEnumKey(m.Context, &winreg.BaseRegEnumKeyRequest{
			Key:   openUsersResp.Key,
			Index: index,
			NameIn: &winreg.UnicodeString{
				MaximumLength: uint16(1024),
			},
			ClassIn: &winreg.UnicodeString{
				MaximumLength: uint16(1024),
			},
			LastWriteTime: nil,
		})

		result := resp.NameOut.Buffer
		if ok, _ := regexp.MatchString(`^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$`, result); ok {
			sids = append(sids, resp.NameOut.Buffer)
		}
	}

	return sids, nil
}
