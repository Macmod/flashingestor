// Package smb provides SMB client functionality for reading files from
// network shares, primarily for GPO-related data collection.
//
// Connection Pooling: FileReader automatically pools TCP connections, SMB sessions,
// and share mounts per server:share combination. This avoids the overhead of
// re-establishing connections for multiple file reads from the same share.
// Call Close() when done to release all pooled resources.
package smb

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/RedTeamPentesting/adauth"
	"github.com/RedTeamPentesting/adauth/smbauth"
	"github.com/oiweiwei/go-smb2.fork"
)

// shareConnection represents a cached connection to an SMB share
type shareConnection struct {
	tcpConn net.Conn
	session *smb2.Session
	share   *smb2.Share
	server  string
	name    string
}

// FileReader provides methods to read files from SMB shares with connection pooling
type FileReader struct {
	creds           *adauth.Credential
	kerberosDialer  adauth.Dialer
	connections     map[string]*shareConnection // key: "server:share"
	mu              sync.RWMutex
}

// NewFileReader creates a new SMB file reader with connection pooling
func NewFileReader(creds *adauth.Credential, kerberosDialer adauth.Dialer) *FileReader {
	return &FileReader{
		creds:          creds,
		kerberosDialer: kerberosDialer,
		connections:    make(map[string]*shareConnection),
	}
}

// getOrCreateConnection returns a cached connection or creates a new one
func (fr *FileReader) getOrCreateConnection(ctx context.Context, server, shareName string) (*shareConnection, error) {
	key := server + ":" + shareName
	
	// Check if we have a cached connection
	fr.mu.RLock()
	conn, exists := fr.connections[key]
	fr.mu.RUnlock()
	
	if exists {
		return conn, nil
	}
	
	// Create new connection
	fr.mu.Lock()
	defer fr.mu.Unlock()
	
	// Double-check after acquiring write lock
	if conn, exists := fr.connections[key]; exists {
		return conn, nil
	}
	
	// Create target and SMB dialer
	target := adauth.NewTarget("host", server)
	target.Port = "445"

	smbDialer, err := smbauth.Dialer(ctx, fr.creds, target, &smbauth.Options{
		KerberosDialer: fr.kerberosDialer,
	})
	if err != nil {
		return nil, fmt.Errorf("setup SMB authentication: %w", err)
	}

	// Create TCP connection
	tcpConn, err := net.Dial("tcp", target.Address())
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target.Address(), err)
	}

	// Create SMB session
	sess, err := smbDialer.DialContext(ctx, tcpConn)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("create session: %w", err)
	}

	// Mount the share
	fs, err := sess.Mount(shareName)
	if err != nil {
		sess.Logoff()
		tcpConn.Close()
		return nil, fmt.Errorf("mount share %s: %w", shareName, err)
	}
	
	conn = &shareConnection{
		tcpConn: tcpConn,
		session: sess,
		share:   fs,
		server:  server,
		name:    shareName,
	}
	
	fr.connections[key] = conn
	return conn, nil
}

// Close closes all cached connections
func (fr *FileReader) Close() {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	
	for _, conn := range fr.connections {
		if conn.share != nil {
			conn.share.Umount()
		}
		if conn.session != nil {
			conn.session.Logoff()
		}
		if conn.tcpConn != nil {
			conn.tcpConn.Close()
		}
	}
	
	fr.connections = make(map[string]*shareConnection)
}

// ReadFile reads a file from a UNC path (e.g., \\server\share\path\to\file.txt)
// and returns its contents as a byte slice. Reuses connections when possible.
func (fr *FileReader) ReadFile(ctx context.Context, uncPath string) ([]byte, error) {
	// Parse UNC path: \\server\share\path\to\file
	server, shareName, filePath, err := parseUNCPathWithServer(uncPath)
	if err != nil {
		return nil, err
	}

	// Get or create connection to this share
	conn, err := fr.getOrCreateConnection(ctx, server, shareName)
	if err != nil {
		return nil, err
	}

	// Open the file
	file, err := conn.share.OpenFile(filePath, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open file %s: %w", filePath, err)
	}
	defer file.Close()

	// Read the file contents
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %w", filePath, err)
	}

	return data, nil
}

// FileExists checks if a file exists at the given UNC path. Reuses connections when possible.
func (fr *FileReader) FileExists(ctx context.Context, uncPath string) (bool, error) {
	server, shareName, filePath, err := parseUNCPathWithServer(uncPath)
	if err != nil {
		return false, err
	}

	// Get or create connection to this share
	conn, err := fr.getOrCreateConnection(ctx, server, shareName)
	if err != nil {
		return false, err
	}

	// Try to stat the file
	_, err = conn.share.Stat(filePath)
	if err != nil {
		if strings.Contains(err.Error(), "file does not exist") || strings.Contains(err.Error(), "object name not found") {
			return false, nil
		}
		return false, fmt.Errorf("stat file %s: %w", filePath, err)
	}

	return true, nil
}

// parseUNCPathWithServer parses a UNC path and returns the server, share name and file path
// Input: \\server\share\path\to\file.txt or //server/share/path/to/file.txt
// Output: server, share, path/to/file.txt
func parseUNCPathWithServer(uncPath string) (string, string, string, error) {
	// Normalize path separators to forward slashes
	uncPath = filepath.ToSlash(uncPath)

	// Remove leading slashes
	uncPath = strings.TrimPrefix(uncPath, "//")
	uncPath = strings.TrimPrefix(uncPath, "\\\\")

	// Split into parts: server/share/path/to/file
	parts := strings.Split(uncPath, "/")
	if len(parts) < 3 {
		return "", "", "", fmt.Errorf("invalid UNC path: %s (expected format: \\\\server\\share\\path)", uncPath)
	}

	// Extract server (parts[0]), share (parts[1]) and path (parts[2:])
	server := parts[0]
	shareName := parts[1]
	filePath := strings.Join(parts[2:], "/")

	return server, shareName, filePath, nil
}
