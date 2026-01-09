package bloodhound

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/config"
	"github.com/Macmod/flashingestor/msrpc"
)

// formatFileSize converts a byte count to a human-readable size string (KB, MB, GB, TB)
func formatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB"}
	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), units[exp])
}

var filteredSids = []string{
	"S-1-5-3", "S-1-5-4", "S-1-5-6", "S-1-2", "S-1-2-0", "S-1-5-17", "S-1-5-18",
	"S-1-5-19", "S-1-5-20", "S-1-0-0", "S-1-0", "S-1-2-1",
}

// isSidFiltered checks if a SID should be excluded from processing (service accounts, NT AUTHORITY, etc.)
func isSidFiltered(sid string) bool {
	return slices.Contains(filteredSids, strings.ToUpper(sid)) ||
		strings.HasPrefix(sid, "S-1-5-80") ||
		strings.HasPrefix(sid, "S-1-5-82") ||
		strings.HasPrefix(sid, "S-1-5-90") ||
		strings.HasPrefix(sid, "S-1-5-96")
}

func getMachineSID(ctx context.Context, auth *config.CredentialMgr, computerName string, computerObjectId string) (string, error) {
	if machineSid, ok := builder.BState().MachineSIDCache.Get(computerObjectId); ok {
		return machineSid.ObjectIdentifier, nil
	}

	rpcObj, err := msrpc.NewSamrRPC(ctx, computerName, auth)
	if err != nil {
		return "", err
	}
	defer rpcObj.Close()

	machineSid, err := rpcObj.GetMachineSid(computerName)
	if err != nil {
		return "", err
	}

	builder.BState().MachineSIDCache.Set(computerObjectId, &builder.Entry{
		ObjectIdentifier: machineSid.String(),
		ObjectTypeRaw:    builder.ComputerObjectType,
	})

	return machineSid.String(), nil
}

// requestNETBIOSNameFromComputer queries a computer's NetBIOS name via UDP port 137
// Returns the NetBIOS name and whether the query was successful
func requestNETBIOSNameFromComputer(ctx context.Context, ipAddress string, timeout time.Duration) (string, bool) {
	// Create a context with timeout
	if timeout == 0 {
		timeout = 1 * time.Second
	}

	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// NetBIOS Name Request packet - matches SharpHound's NameRequest
	// This is a standard NBSTAT query for "*" (wildcard)
	packet := []byte{
		0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
		0x00, 0x01,
	}

	// Set up UDP connection
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(queryCtx, "udp", ipAddress+":137")
	if err != nil {
		return "", false
	}
	defer conn.Close()

	// Set deadline for the connection
	deadline, ok := queryCtx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}

	// Send the query
	_, err = conn.Write(packet)
	if err != nil {
		return "", false
	}

	// Read the response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return "", false
	}

	// Response must be at least 90 bytes (SharpHound compatibility check)
	// This ensures we have enough data to read the first NetBIOS name
	if n < 90 {
		return "", false
	}

	// Extract NetBIOS name from fixed offset 57 (16 bytes)
	// This matches SharpHound's approach - simpler and more reliable than full parsing
	// Offset 57 is where the first NetBIOS name entry starts in a standard NBSTAT response
	netbiosName := string(response[57:73])

	// Trim null bytes and spaces
	netbiosName = strings.Trim(netbiosName, "\x00 ")

	if netbiosName == "" {
		return "", false
	}

	return strings.ToUpper(netbiosName), true
}

// resolveHostname resolves a hostname to a computer SID using RPC queries, NetBIOS and caches
func resolveHostname(ctx context.Context, auth *config.CredentialMgr, host string, domain string) (string, bool) {
	rpcObj, err := msrpc.NewWkssvcRPC(ctx, host, auth)
	if err == nil {
		defer rpcObj.Close()

		wkstaInfo, err := rpcObj.GetWkstaInfo(ctx)
		if err == nil {
			if wkstaInfo.LANGroup != "" {
				if resolvedDomain, ok := builder.BState().NetBIOSDomainCache.Get(domain); ok && resolvedDomain != "" {
					domain = resolvedDomain
				}
			}
			return builder.ResolveHostnameInCaches(wkstaInfo.ComputerName, domain)
		}
	}

	if netbiosName, ok := requestNETBIOSNameFromComputer(ctx, host, config.NETBIOS_TIMEOUT); ok && netbiosName != "" {
		host = netbiosName
	}

	return builder.ResolveHostnameInCaches(host, domain)
}
