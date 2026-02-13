package bloodhound

import (
	"context"
	"fmt"
	"strings"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/config"
	"github.com/RedTeamPentesting/adauth/smbauth"
	"github.com/oiweiwei/go-msrpc/smb2"
)

// collectIsWebClientRunning checks if the WebClient service is running by testing WebDAV access via SMB
func (rc *RemoteCollector) collectIsWebClientRunning(ctx context.Context, targetHost string) builder.IsWebClientRunningAPIResult {
	result := builder.IsWebClientRunningAPIResult{
		APIResult: builder.APIResult{Collected: false},
	}

	if rc.auth.Creds() == nil {
		errStr := "credential not available"
		result.FailureReason = &errStr
		return result
	}

	creds := rc.auth.Creds()
	target := rc.auth.NewTarget("host", targetHost)

	if target.Port == "" {
		target.Port = "445"
	}

	smbDialer, err := smbauth.Dialer(ctx, creds, target, &smbauth.Options{
		KerberosDialer: rc.auth.Dialer(config.KERBEROS_TIMEOUT),
	})

	if err != nil {
		errStr := fmt.Sprintf("failed to setup SMB authentication: %v", err)
		result.FailureReason = &errStr
		return result
	}

	pipe := &smb2.NamedPipe{
		Address:         target.AddressWithoutPort(),
		Port:            445,
		Dialer:          smbDialer,
		NetworkDialFunc: rc.auth.Dialer(config.SMB_TIMEOUT).DialContext,
		ShareName:       "IPC$",
		Name:            "DAV RPC SERVICE",
		Timeout:         config.SMB_TIMEOUT,
	}

	// Try to connect to the named pipe
	err = pipe.Connect(ctx)
	if err == nil {
		// Successfully connected to the pipe, WebClient is running
		pipe.Close()
		exists := true
		result.Result = &exists
		result.Collected = true
	} else if strings.Contains(err.Error(), "file does not exist") {
		// Pipe exists but not active (WebClient not running)
		exists := false
		result.Result = &exists
		result.Collected = true
	} else {
		// Connection error
		errStr := fmt.Sprintf("error connecting to DAV RPC SERVICE pipe: %v", err)
		result.FailureReason = &errStr
	}

	return result
}
