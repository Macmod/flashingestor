package bloodhound

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/config"
)

// formatMethodTimes creates a colored string showing timing for each collection method
func formatMethodTimes(methodTimes map[string]time.Duration) string {
	// Define method order matching actual execution order in remote_computers.go
	methodOrder := []string{
		"_rpc_winreg", "_rpc_lsat", "_rpc_samr", "_rpc_lsad", "_rpc_wkssvc", "_rpc_srvsvc",
		"regsessions", "ntlmregistry", "dcregistry", "smbinfo",
		"localgroups", "userrights", "loggedon", "sessions",
		"webclient", "ldapservices", "certservices", "caregistry",
	}

	result := "{"
	first := true
	for _, method := range methodOrder {
		duration, exists := methodTimes[method]
		if !exists {
			continue
		}
		if !first {
			result += ", "
		}
		color := "[green]"
		if duration >= time.Second {
			color = "[red]"
		}
		result += "[blue]" + method + "[-]: " + color + duration.String() + "[-]"
		first = false
	}
	result += "}"
	return result
}

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

func getMachineSID(ctx context.Context, rpcMgr *RPCManager, computerObjectId string) (string, error) {
	if machineSid, ok := builder.BState().MachineSIDCache.Get(computerObjectId); ok {
		return machineSid.ObjectIdentifier, nil
	}

	rpcObj, err := rpcMgr.GetOrCreateSamrRPC(ctx)
	if err != nil {
		return "", err
	}

	machineSid, err := rpcObj.GetMachineSid(rpcMgr.GetTargetHost())
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
func resolveHostname(ctx context.Context, rpcMgr *RPCManager, domain string) (string, bool) {
	rpcObj, err := rpcMgr.GetOrCreateWkssvcRPC(ctx)
	if err == nil {
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

	host := rpcMgr.GetTargetHost()
	if netbiosName, ok := requestNETBIOSNameFromComputer(ctx, host, config.NETBIOS_TIMEOUT); ok && netbiosName != "" {
		host = netbiosName
	}

	return builder.ResolveHostnameInCaches(host, domain)
}

// isValidLocalGroupRid checks if a RID corresponds to a valid local group
func isValidLocalGroupRid(rid int) bool {
	switch LocalGroupRids(rid) {
	case LocalGroupAdministrators, LocalGroupRemoteDesktopUsers, LocalGroupDcomUsers, LocalGroupPSRemote:
		return true
	default:
		return false
	}
}

// deduplicatePrincipals removes duplicate principals based on ObjectIdentifier
func deduplicatePrincipals(principals []builder.TypedPrincipal) []builder.TypedPrincipal {
	seen := make(map[string]bool)
	result := []builder.TypedPrincipal{}

	for _, p := range principals {
		if !seen[p.ObjectIdentifier] {
			seen[p.ObjectIdentifier] = true
			result = append(result, p)
		}
	}

	return result
}

// splitGPLinkProperty parses the gpLink attribute and returns individual links
func splitGPLinkProperty(gpLink string) []GPLink {
	// Format: [LDAP://cn={...},cn=policies,cn=system,DC=...;0][LDAP://...;2]
	// Status: 0 = unenforced, 2 = enforced, 1 = disabled
	var links []GPLink

	// Split by ][  to get individual link blocks
	gpLink = strings.TrimSpace(gpLink)
	if gpLink == "" {
		return links
	}

	// Remove outer brackets and split
	blocks := strings.Split(gpLink, "][")

	for _, block := range blocks {
		// Clean up brackets
		block = strings.Trim(block, "[]")
		if block == "" {
			continue
		}

		// Split by last semicolon to separate DN from status
		lastSemicolon := strings.LastIndex(block, ";")
		if lastSemicolon == -1 {
			continue
		}

		ldapPath := block[:lastSemicolon]
		status := block[lastSemicolon+1:]

		// Extract DN from LDAP:// prefix
		dn := strings.TrimPrefix(ldapPath, "LDAP://")
		dn = strings.TrimPrefix(dn, "ldap://")

		links = append(links, GPLink{
			DN:     dn,
			Status: status,
		})
	}

	return links
}

// GPLink represents a single GPO link with its status
type GPLink struct {
	DN     string
	Status string // "0" = unenforced, "2" = enforced, "1" = disabled
}

// removePrincipal removes a principal from the list by ObjectIdentifier
func removePrincipal(principals []builder.TypedPrincipal, objectID string) []builder.TypedPrincipal {
	result := []builder.TypedPrincipal{}
	for _, p := range principals {
		if p.ObjectIdentifier != objectID {
			result = append(result, p)
		}
	}
	return result
}

// removePrincipalsByType removes all principals of a specific type from the list
func removePrincipalsByType(principals []builder.TypedPrincipal, objectType string) []builder.TypedPrincipal {
	result := []builder.TypedPrincipal{}
	for _, p := range principals {
		if p.ObjectType != objectType {
			result = append(result, p)
		}
	}
	return result
}

// decodeUTF16 removes UTF-16 BOM and null bytes
func decodeUTF16(s string) string {
	// Remove UTF-16 LE BOM (FF FE)
	s = strings.TrimPrefix(s, "\xFF\xFE")
	// Remove UTF-16 BE BOM (FE FF)
	s = strings.TrimPrefix(s, "\xFE\xFF")
	// Remove null bytes (common in UTF-16 LE files)
	s = strings.ReplaceAll(s, "\x00", "")
	return s
}

// formatSuccessRate formats a success count/total as percentage string
func formatSuccessRate(success, total int) string {
	if total == 0 {
		return "0/0"
	}
	percent := float64(success) / float64(total) * 100.0
	return fmt.Sprintf("%d/%d (%.1f%%)", success, total, percent)
}

// checkPortOpen attempts to connect to a port
type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

func checkPortOpen(ctx context.Context, dialer Dialer, host string, port int) (bool, error) {
	address := net.JoinHostPort(host, strconv.Itoa(port))

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	return true, nil
}

// parseDNComponents splits a DN into components, treating all DC= parts as a single domain component
// Example: "OU=A,OU=B,DC=CORP,DC=LOCAL" -> ["OU=A,OU=B,DC=CORP,DC=LOCAL", "OU=B,DC=CORP,DC=LOCAL", "DC=CORP,DC=LOCAL"]
func parseDNComponents(dn string) []string {
	if dn == "" {
		return nil
	}

	// Find the first DC= component (case-insensitive)
	upperDN := strings.ToUpper(dn)
	dcIndex := strings.Index(upperDN, ",DC=")
	if dcIndex == -1 {
		// No DC components, just return the DN itself
		return []string{dn}
	}

	// Pre-allocate slice for components (estimate: depth of 5-8 is typical)
	components := make([]string, 0, 8)

	// Add full DN first
	components = append(components, dn)

	// Walk through and find each comma before the DC= part
	// Use slicing to reference substrings without allocation
	pos := 0
	for pos < dcIndex {
		commaIdx := strings.Index(dn[pos:dcIndex], ",")
		if commaIdx == -1 {
			break
		}
		pos += commaIdx + 1
		// Slice from current position to end (includes domain part)
		components = append(components, dn[pos:])
	}

	// Add domain component at the end (everything from dcIndex+1)
	components = append(components, dn[dcIndex+1:])

	return components
}

// getDomainFromComputerSID extracts the domain name from a computer SID using cached domain mappings
func getDomainFromComputerSID(computerSID string) string {
	// Extract domain SID by removing the RID (last component)
	sidParts := strings.Split(computerSID, "-")
	if len(sidParts) < 4 {
		return ""
	}
	domainSID := strings.Join(sidParts[:len(sidParts)-1], "-")

	// Look up domain name from domain SID
	domain, _ := builder.BState().SIDDomainCache.Get(domainSID)
	return domain
}
