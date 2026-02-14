package smb

// Package smb provides SMB client functionality for reading files from
// network shares, primarily for GPO-related data collection.
//
// Connection Pooling: FileReader automatically pools TCP connections, SMB sessions,
// and share mounts per server:share combination. This avoids the overhead of
// re-establishing connections for multiple file reads from the same share.
// Call Close() when done to release all pooled resources.

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/Macmod/flashingestor/config"
	"github.com/RedTeamPentesting/adauth/smbauth"
	"github.com/oiweiwei/go-smb2.fork"
	"golang.org/x/sync/singleflight"
)

// shareConnection represents a cached connection to an SMB share
type shareConnection struct {
	mu      sync.Mutex
	tcpConn net.Conn
	session *smb2.Session
	share   *smb2.Share
	server  string
	name    string
}

// FileReader provides methods to read files from SMB shares with connection pooling
type FileReader struct {
	auth        *config.CredentialMgr
	connections map[string]*shareConnection // key: "server:share"
	mu          sync.RWMutex                // protects connections map (Go maps are not thread-safe)
	group       singleflight.Group          // prevents duplicate concurrent connection attempts
}

// NewFileReader creates a new SMB file reader with connection pooling
func NewFileReader(auth *config.CredentialMgr) *FileReader {
	return &FileReader{
		auth:        auth,
		connections: make(map[string]*shareConnection),
	}
}

// getOrCreateConnection returns a cached connection or creates a new one.
//
// Concurrency design:
// - RWMutex (fr.mu): Protects the connections map from concurrent access (Go maps are not thread-safe)
// - Singleflight (fr.group): Deduplicates concurrent connection attempts for the SAME key
//
// Both are necessary:
// - Without RWMutex: map access would panic due to concurrent reads/writes
// - Without singleflight: multiple goroutines could create duplicate connections for the same share
func (fr *FileReader) getOrCreateConnection(server, shareName string) (*shareConnection, error) {
	key := server + ":" + shareName

	// Fast path: check with read lock (RWMutex allows multiple concurrent readers)
	fr.mu.RLock()
	conn, exists := fr.connections[key]
	fr.mu.RUnlock()
	if exists {
		return conn, nil
	}

	// Slow path: use singleflight to ensure only one goroutine creates the connection
	// for this specific key. Other goroutines requesting the same key will wait and
	// receive the same result, avoiding duplicate network operations.
	result, err, _ := fr.group.Do(key, func() (interface{}, error) {
		// Double-check: another goroutine might have created it while we waited
		fr.mu.RLock()
		conn, exists := fr.connections[key]
		fr.mu.RUnlock()
		if exists {
			return conn, nil
		}

		// Create the connection outside of any lock to avoid blocking other shares.
		// This is the key benefit: goroutines creating connections for DIFFERENT shares
		// can proceed in parallel, only serializing the brief map insertion below.
		newConn, err := fr.createConnection(server, shareName)
		if err != nil {
			return nil, err
		}

		// Store the connection with a brief write lock.
		// RWMutex is required because Go maps are not safe for concurrent access.
		fr.mu.Lock()
		fr.connections[key] = newConn
		fr.mu.Unlock()

		return newConn, nil
	})

	if err != nil {
		return nil, err
	}
	return result.(*shareConnection), nil
}

// createConnection creates a new SMB connection without holding any locks
func (fr *FileReader) createConnection(server, shareName string) (*shareConnection, error) {
	// Create target and SMB dialer
	target := fr.auth.NewTarget("host", server)
	target.Port = "445"

	ctx, cancel := context.WithTimeout(context.Background(), config.SMB_TIMEOUT)
	defer cancel()
	smbDialer, err := smbauth.Dialer(ctx, fr.auth.Creds(), target, &smbauth.Options{
		KerberosDialer: fr.auth.Dialer(config.KERBEROS_TIMEOUT),
	})
	if err != nil {
		return nil, fmt.Errorf("setup SMB authentication: %w", err)
	}

	// Create TCP connection
	tcpConnDialer := fr.auth.Dialer(config.SMB_TIMEOUT)
	tcpConn, err := tcpConnDialer.Dial("tcp", target.Address())
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target.Address(), err)
	}

	// Create SMB session
	sess, err := smbDialer.Dial(tcpConn)
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

	return &shareConnection{
		tcpConn: tcpConn,
		session: sess,
		share:   fs,
		server:  server,
		name:    shareName,
	}, nil
}

// close releases all resources for this connection
func (sc *shareConnection) close() {
	if sc.share != nil {
		sc.share.Umount()
	}
	if sc.session != nil {
		sc.session.Logoff()
	}
	if sc.tcpConn != nil {
		sc.tcpConn.Close()
	}
}

// Close closes all cached connections
func (fr *FileReader) Close() {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	for _, conn := range fr.connections {
		conn.close()
	}

	fr.connections = make(map[string]*shareConnection)
}

// ReadFile reads a file from a UNC path (e.g., \\server\share\path\to\file.txt)
// and returns its contents as a byte slice. Reuses connections when possible.
func (fr *FileReader) ReadFile(uncPath string) ([]byte, error) {
	// Parse UNC path: \\server\share\path\to\file
	server, shareName, filePath, err := parseUNCPathWithServer(uncPath)
	if err != nil {
		return nil, err
	}

	conn, err := fr.getOrCreateConnection(server, shareName)
	if err != nil {
		return nil, err
	}

	file, err := conn.share.OpenFile(filePath, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open file %s: %w", filePath, err)
	}

	data, readErr := io.ReadAll(file)
	file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read file %s: %w", filePath, readErr)
	}

	return data, nil
}

// FileExists checks if a file exists at the given UNC path. Reuses connections when possible.
func (fr *FileReader) FileExists(uncPath string) (bool, error) {
	server, shareName, filePath, err := parseUNCPathWithServer(uncPath)
	if err != nil {
		return false, err
	}

	conn, err := fr.getOrCreateConnection(server, shareName)
	if err != nil {
		return false, err
	}

	_, statErr := conn.share.Stat(filePath)
	if statErr != nil {
		if strings.Contains(statErr.Error(), "file does not exist") || strings.Contains(statErr.Error(), "object name not found") {
			return false, nil
		}
		return false, fmt.Errorf("stat file %s: %w", filePath, statErr)
	}
	return true, nil
}

// parseUNCPathWithServer parses a UNC path and returns the server, share name and file path
// Input: \\server\share\path\to\file.txt or //server/share/path/to/file.txt
// Output: server, share, path/to/file.txt
func parseUNCPathWithServer(uncPath string) (string, string, string, error) {
	// Remove leading slashes (handle both \\ and //)
	uncPath = strings.TrimPrefix(uncPath, "\\\\")
	uncPath = strings.TrimPrefix(uncPath, "//")

	// Split into parts: server/share/path/to/file
	parts := strings.SplitN(uncPath, "\\", 3)
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("invalid UNC path: %s (expected format: \\\\server\\share\\path)", uncPath)
	}

	// Extract server (parts[0]), share (parts[1]) and path (parts[2])
	server := parts[0]
	shareName := parts[1]
	filePath := ""
	if len(parts) > 2 {
		filePath = parts[2]
	}

	return server, shareName, filePath, nil
}
