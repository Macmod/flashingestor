package msrpc

import (
	"context"
	"fmt"
	"net"

	"github.com/Macmod/flashingestor/config"
	"github.com/RedTeamPentesting/adauth/dcerpcauth"
	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	lsad "github.com/oiweiwei/go-msrpc/msrpc/lsad/lsarpc/v0"
	lsat "github.com/oiweiwei/go-msrpc/msrpc/lsat/lsarpc/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/rrp/winreg/v1"
	"github.com/oiweiwei/go-msrpc/msrpc/samr/samr/v1"
	"github.com/oiweiwei/go-msrpc/msrpc/srvs/srvsvc/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/wkst/wkssvc/v1"
)

// BaseRPC contains the common fields for all RPC client types
type BaseRPC struct {
	Conn    dcerpc.Conn
	Context context.Context
	Binding string
}

func (b *BaseRPC) Close() {
	b.Conn.Close(b.Context)
}

// WinregRPC wraps a Windows Registry RPC client
type WinregRPC struct {
	BaseRPC
	Client winreg.WinregClient
}

// SamrRPC wraps a SAM RPC client
type SamrRPC struct {
	BaseRPC
	Client samr.SamrClient
}

// SrvsvcRPC wraps a Server Service RPC client
type SrvsvcRPC struct {
	BaseRPC
	Client srvsvc.SrvsvcClient
}

// LsatRPC wraps an LSA RPC client (local)
type LsatRPC struct {
	BaseRPC
	Client lsat.LsarpcClient
}

// LsadRPC wraps an LSA RPC client (domain)
type LsadRPC struct {
	BaseRPC
	Client lsad.LsarpcClient
}

// WkssvcRPC wraps a Workstation Service RPC client
type WkssvcRPC struct {
	BaseRPC
	Client wkssvc.WkssvcClient
}

// newBaseRPC creates the common RPC connection
func newBaseRPC(ctx context.Context, targetHost string, auth *config.CredentialMgr) (BaseRPC, error) {
	// Get credentials for DCERPC
	target := auth.NewTarget("host", targetHost)

	dcerpcOptions := &dcerpcauth.Options{
		KerberosDialer: auth.Dialer(config.KERBEROS_TIMEOUT),
	}

	dcerpcOpts, err := dcerpcauth.AuthenticationOptions(ctx, auth.Creds(), target, dcerpcOptions)
	if err != nil {
		return BaseRPC{}, fmt.Errorf("failed to get auth options: %w", err)
	}

	/* TODO (Future): Review if the endpoint mapper is really needed */
	epm := epm.EndpointMapper(ctx,
		net.JoinHostPort(target.AddressWithoutPort(), "135"),
		dcerpc.WithInsecure(),
		dcerpc.WithTimeout(config.DCERPC_EPM_TIMEOUT),
	)
	dcerpcOpts = append(dcerpcOpts, epm)

	// Create binding string
	binding := fmt.Sprintf("ncacn_np:%s", targetHost)

	// Connect to the RPC service
	conn, err := dcerpc.Dial(ctx, binding, dcerpcOpts...)
	if err != nil {
		return BaseRPC{}, fmt.Errorf("connection failed: %w", err)
	}

	return BaseRPC{
		Conn:    conn,
		Context: ctx,
		Binding: binding,
	}, nil
}

// NewWinregRPC creates a new Windows Registry RPC client
func NewWinregRPC(ctx context.Context, targetHost string, auth *config.CredentialMgr) (*WinregRPC, error) {
	base, err := newBaseRPC(ctx, targetHost, auth)
	if err != nil {
		return nil, err
	}

	client, err := winreg.NewWinregClient(base.Context, base.Conn, dcerpc.WithInsecure())
	if err != nil {
		base.Close()
		return nil, fmt.Errorf("failed to bind winreg client: %w", err)
	}

	return &WinregRPC{
		BaseRPC: base,
		Client:  client,
	}, nil
}

// NewSamrRPC creates a new SAM RPC client
func NewSamrRPC(ctx context.Context, targetHost string, auth *config.CredentialMgr) (*SamrRPC, error) {
	base, err := newBaseRPC(ctx, targetHost, auth)
	if err != nil {
		return nil, err
	}

	client, err := samr.NewSamrClient(base.Context, base.Conn, dcerpc.WithSeal())
	if err != nil {
		base.Close()
		return nil, fmt.Errorf("failed to bind samr client: %w", err)
	}

	return &SamrRPC{
		BaseRPC: base,
		Client:  client,
	}, nil
}

// NewSrvsvcRPC creates a new Server Service RPC client
func NewSrvsvcRPC(ctx context.Context, targetHost string, auth *config.CredentialMgr) (*SrvsvcRPC, error) {
	base, err := newBaseRPC(ctx, targetHost, auth)
	if err != nil {
		return nil, err
	}

	client, err := srvsvc.NewSrvsvcClient(base.Context, base.Conn, dcerpc.WithInsecure())
	if err != nil {
		base.Close()
		return nil, fmt.Errorf("failed to create srvsvc client: %w", err)
	}

	return &SrvsvcRPC{
		BaseRPC: base,
		Client:  client,
	}, nil
}

// NewLsatRPC creates a new LSA RPC client (local)
func NewLsatRPC(ctx context.Context, targetHost string, auth *config.CredentialMgr) (*LsatRPC, error) {
	base, err := newBaseRPC(ctx, targetHost, auth)
	if err != nil {
		return nil, err
	}

	client, err := lsat.NewLsarpcClient(base.Context, base.Conn, dcerpc.WithSeal())
	if err != nil {
		base.Close()
		return nil, fmt.Errorf("failed to create lsa client: %w", err)
	}

	return &LsatRPC{
		BaseRPC: base,
		Client:  client,
	}, nil
}

// NewLsadRPC creates a new LSA RPC client (domain)
func NewLsadRPC(ctx context.Context, targetHost string, auth *config.CredentialMgr) (*LsadRPC, error) {
	base, err := newBaseRPC(ctx, targetHost, auth)
	if err != nil {
		return nil, err
	}

	client, err := lsad.NewLsarpcClient(base.Context, base.Conn, dcerpc.WithSeal())
	if err != nil {
		base.Close()
		return nil, fmt.Errorf("failed to create lsa client: %w", err)
	}

	return &LsadRPC{
		BaseRPC: base,
		Client:  client,
	}, nil
}

// NewWkssvcRPC creates a new Workstation Service RPC client
func NewWkssvcRPC(ctx context.Context, targetHost string, auth *config.CredentialMgr) (*WkssvcRPC, error) {
	base, err := newBaseRPC(ctx, targetHost, auth)
	if err != nil {
		return nil, err
	}

	client, err := wkssvc.NewWkssvcClient(base.Context, base.Conn, dcerpc.WithInsecure())
	if err != nil {
		base.Close()
		return nil, fmt.Errorf("failed to create wkssvc client: %w", err)
	}

	return &WkssvcRPC{
		BaseRPC: base,
		Client:  client,
	}, nil
}
