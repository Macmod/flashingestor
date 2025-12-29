package msrpc

import (
	"context"
	"fmt"
	"strings"

	"github.com/oiweiwei/go-msrpc/msrpc/wkst/wkssvc/v1"
)

type LoggedOnUser struct {
	Username string
	Domain   string
}

func (m *MSRPC) GetLoggedOnUsers(ctx context.Context) ([]LoggedOnUser, error) {
	client, ok := m.Client.(wkssvc.WkssvcClient)
	if !ok {
		return nil, fmt.Errorf("wkssvc client type assertion failed")
	}

	userInfo := wkssvc.WorkstationUserEnum{
		Level: 1,
		WorkstationUserInfo: &wkssvc.WorkstationUserEnum_WorkstationUserInfo{
			Value: &wkssvc.WorkstationUserInfo_Level1{
				Level1: &wkssvc.WorkstationUserInfo1Container{
					EntriesRead: 0,
					Buffer:      nil,
				},
			},
		},
	}

	resp, err := client.UserEnum(m.Context, &wkssvc.UserEnumRequest{
		ServerName:             m.Binding,
		UserInfo:               &userInfo,
		PreferredMaximumLength: 0xFFFFFFFF,
		Resume:                 0,
	})

	if err != nil {
		return nil, fmt.Errorf("NetWkstaUserEnum failed: %w", err)
	}

	loggedOnUsers := make([]LoggedOnUser, 0)

	if resp != nil {
		for _, user := range resp.UserInfo.WorkstationUserInfo.Value.(*wkssvc.WorkstationUserInfo_Level1).Level1.Buffer {
			if user == nil {
				continue
			}

			username := user.UserName
			logonDomain := user.LogonDomain

			loggedOnUsers = append(loggedOnUsers, LoggedOnUser{
				Username: username,
				Domain:   strings.ToUpper(logonDomain),
			})
		}
	}

	return loggedOnUsers, nil
}
