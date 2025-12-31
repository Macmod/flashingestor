package msrpc

import (
	"context"
	"fmt"

	"github.com/oiweiwei/go-msrpc/msrpc/srvs/srvsvc/v3"
)

type Session struct {
	ClientName string
	UserName   string
	Time       uint32
	IdleTime   uint32
}

func (m *MSRPC) GetSessions(ctx context.Context) ([]Session, error) {
	sessions := make([]Session, 0)

	client, ok := m.Client.(srvsvc.SrvsvcClient)
	if !ok {
		return nil, fmt.Errorf("srvsvc client type assertion failed")
	}

	info := srvsvc.SessionEnum{
		Level: 10,
		SessionInfo: &srvsvc.SessionEnumUnion{
			Value: &srvsvc.SessionEnumUnion_Level10{
				Level10: &srvsvc.SessionInfo10Container{
					EntriesRead: 0,
					Buffer:      nil,
				},
			},
		},
	}

	resp, err := client.SessionEnum(m.Context, &srvsvc.SessionEnumRequest{
		ServerName:             m.Binding,
		ClientName:             "",
		UserName:               "",
		Info:                   &info,
		PreferredMaximumLength: 0xFFFFFFFF,
		Resume:                 0,
	})

	if err != nil {
		return nil, fmt.Errorf("NetSessionEnum failed: %w", err)
	}

	if resp != nil && resp.Info != nil && resp.Info.SessionInfo != nil && resp.Info.SessionInfo.Value != nil {
		level10, ok := resp.Info.SessionInfo.Value.(*srvsvc.SessionEnumUnion_Level10)
		if !ok || level10 == nil || level10.Level10 == nil {
			return sessions, nil
		}

		for _, session := range level10.Level10.Buffer {
			sessions = append(sessions, Session{
				ClientName: session.ClientName,
				UserName:   session.UserName,
				Time:       session.Time,
				IdleTime:   session.IdleTime,
			})
		}
	}

	return sessions, nil
}
