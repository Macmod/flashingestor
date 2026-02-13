package msrpc

import (
	"fmt"
	"regexp"

	"github.com/oiweiwei/go-msrpc/msrpc/rrp/winreg/v1"
)

var sidRegex = regexp.MustCompile(`^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$`)

func (m *WinregRPC) GetSessionsFromRegistry() ([]string, error) {
	sids := make([]string, 0)

	openUsersResp, err := m.Client.OpenUsers(m.Context, &winreg.OpenUsersRequest{
		DesiredAccess: winreg.KeyEnumerateSubKeys,
	})

	if err != nil {
		return nil, fmt.Errorf("OpenUsers failed: %w", err)
	}

	var resp *winreg.BaseRegEnumKeyResponse
	for index := uint32(0); err == nil; index++ {
		resp, err = m.Client.BaseRegEnumKey(m.Context, &winreg.BaseRegEnumKeyRequest{
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

		if err != nil {
			// We could continue here, but for now it's better to stop at
			// unknown errors
			return sids, fmt.Errorf("BaseRegEnumKey failed: %w", err)
		}

		if resp == nil || resp.NameOut == nil {
			// We could continue here, but for now it's better to stop at
			// unknown errors
			return sids, fmt.Errorf("BaseRegEnumKey returned an empty response")
		}

		result := resp.NameOut.Buffer
		if sidRegex.MatchString(result) {
			sids = append(sids, resp.NameOut.Buffer)
		}
	}

	return sids, nil
}
