package msrpc

import (
	"context"
	"fmt"

	"github.com/oiweiwei/go-msrpc/msrpc/wkst/wkssvc/v1"
)

type WkstaInfo struct {
	PlatformID   uint32
	ComputerName string
	LANGroup     string
	VerMajor     uint32
	VerMinor     uint32
}

func (m *WkssvcRPC) GetWkstaInfo(ctx context.Context) (*WkstaInfo, error) {
	resp, err := m.Client.GetInfo(ctx, &wkssvc.GetInfoRequest{
		ServerName: m.Binding,
		Level:      100,
	})

	if err != nil {
		return nil, fmt.Errorf("NetrWkstaGetInfo failed: %w", err)
	}

	if resp == nil || resp.WorkstationInfo == nil {
		return nil, fmt.Errorf("NetrWkstaGetInfo returned empty response")
	}

	wksInfoVal, ok := resp.WorkstationInfo.Value.(*wkssvc.WorkstationInfo_100)
	if !ok || wksInfoVal.WorkstationInfo100 == nil {
		return nil, fmt.Errorf("NetrWkstaGetInfo returned unexpected response format")
	}

	wksInfo := wksInfoVal.WorkstationInfo100
	info := &WkstaInfo{
		PlatformID:   wksInfo.PlatformID,
		ComputerName: wksInfo.ComputerName,
		LANGroup:     wksInfo.LANGroup,
		VerMajor:     wksInfo.VerMajor,
		VerMinor:     wksInfo.VerMinor,
	}

	return info, nil
}
