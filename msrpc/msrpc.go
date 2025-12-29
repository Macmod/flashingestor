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

// Custom type for friendly implementation of RPCs
type MSRPC struct {
	Conn    dcerpc.Conn
	Context context.Context
	Binding string
	Client  interface{}
}

func (m *MSRPC) Close() {
	m.Conn.Close(m.Context)
}

func NewMSRPC(ctx context.Context, targetHost string, auth *config.CredentialMgr) (MSRPC, error) {
	// Get credentials for DCERPC
	target := auth.NewTarget("host", targetHost)

	dcerpcOptions := &dcerpcauth.Options{
		KerberosDialer: auth.Dialer(config.KERBEROS_TIMEOUT),
	}

	dcerpcOpts, err := dcerpcauth.AuthenticationOptions(ctx, auth.Creds(), target, dcerpcOptions)
	if err != nil {
		return MSRPC{}, fmt.Errorf("failed to get auth options: %w", err)
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
		return MSRPC{}, fmt.Errorf("connection failed: %w", err)
	}

	return MSRPC{
		Conn:    conn,
		Context: ctx,
		Binding: binding,
	}, nil
}

// Helpers for binding specific clients
func (m *MSRPC) BindWinregClient() error {
	client, err := winreg.NewWinregClient(m.Context, m.Conn, dcerpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("failed to bind winreg client: %w", err)
	}

	m.Client = client
	return nil
}

func (m *MSRPC) BindSamrClient() error {
	client, err := samr.NewSamrClient(m.Context, m.Conn, dcerpc.WithSeal())
	if err != nil {
		return fmt.Errorf("failed to bind samr client: %w", err)
	}

	m.Client = client
	return nil
}

func (m *MSRPC) BindSrvsvcClient() error {
	client, err := srvsvc.NewSrvsvcClient(m.Context, m.Conn, dcerpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("failed to create srvsvc client: %w", err)
	}

	m.Client = client
	return nil
}

func (m *MSRPC) BindLsatClient() error {
	client, err := lsat.NewLsarpcClient(m.Context, m.Conn, dcerpc.WithSeal())
	if err != nil {
		return fmt.Errorf("failed to create lsa client: %w", err)
	}
	m.Client = client
	return nil
}

func (m *MSRPC) BindLsadClient() error {
	client, err := lsad.NewLsarpcClient(m.Context, m.Conn, dcerpc.WithSeal())
	if err != nil {
		return fmt.Errorf("failed to create lsa client: %w", err)
	}
	m.Client = client
	return nil
}

func (m *MSRPC) BindWkssvcClient() error {
	client, err := wkssvc.NewWkssvcClient(m.Context, m.Conn, dcerpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("failed to create wkssvc client: %w", err)
	}
	m.Client = client
	return nil
}
