package config

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/RedTeamPentesting/adauth"
	"h12.io/socks"
)

// CustomDialer wraps a net.Dialer to use CustomResolver's cache.
// If socksDial is set, it is used for all connections and local DNS
// resolution is skipped so the SOCKS proxy resolves the hostname
// (socks5h-like behavior). For socks4 the hostname must already be
// an IP; use socks4a or socks5 for remote name resolution.
type CustomDialer struct {
	net.Dialer
	resolver  *CustomResolver
	socksDial func(network, address string) (net.Conn, error)
}

func (cd *CustomDialer) Dial(network, address string) (net.Conn, error) {
	return cd.DialContext(context.Background(), network, address)
}

func (cd *CustomDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// If a SOCKS dialer is configured, delegate everything to it.
	// Hostnames are passed through so the proxy handles resolution.
	if cd.socksDial != nil {
		// h12.io/socks does not expose a DialContext; honor ctx via a
		// goroutine + cancellation so ctx timeouts are respected.
		type result struct {
			conn net.Conn
			err  error
		}
		ch := make(chan result, 1)
		go func() {
			c, err := cd.socksDial(network, address)
			ch <- result{c, err}
		}()
		select {
		case <-ctx.Done():
			// Best effort: close the conn if it arrived after cancel
			go func() {
				r := <-ch
				if r.conn != nil {
					r.conn.Close()
				}
			}()
			return nil, ctx.Err()
		case r := <-ch:
			return r.conn, r.err
		}
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	// Skip resolution if already an IP
	if net.ParseIP(host) != nil {
		return cd.Dialer.DialContext(ctx, network, address)
	}

	// Use cached resolver if available, otherwise use default resolution
	if cd.resolver != nil {
		ips, err := cd.resolver.LookupHost(ctx, host)
		if err != nil {
			return nil, err
		}
		resolvedAddr := net.JoinHostPort(ips[0], port)
		return cd.Dialer.DialContext(ctx, network, resolvedAddr)
	}

	// Fallback to default dialer behavior (uses system DNS)
	return cd.Dialer.DialContext(ctx, network, address)
}

type CredentialMgr struct {
	credential  *adauth.Credential
	useKerberos bool
	socksProxy  string
}

func NewCredentialMgr(credential *adauth.Credential, useKerberos bool) *CredentialMgr {
	return &CredentialMgr{
		credential:  credential,
		useKerberos: useKerberos,
	}
}

func (a *CredentialMgr) Creds() *adauth.Credential {
	return a.credential
}

func (a *CredentialMgr) SetDC(dc string) {
	a.credential.SetDC(dc)
}

// SetSocksProxy configures a SOCKS proxy URI (e.g. socks5://127.0.0.1:1080)
// to be used by every Dialer this manager produces. An empty string disables
// the proxy.
func (a *CredentialMgr) SetSocksProxy(uri string) {
	a.socksProxy = uri
}

func (a *CredentialMgr) SocksProxy() string {
	return a.socksProxy
}

func (a *CredentialMgr) Kerberos() bool {
	return a.useKerberos
}

func (a *CredentialMgr) Dialer(timeout time.Duration) *CustomDialer {
	dialer := &CustomDialer{
		Dialer: net.Dialer{Timeout: timeout},
	}

	if a.credential != nil && a.credential.Resolver != nil {
		if customResolver, ok := a.credential.Resolver.(*CustomResolver); ok {
			dialer.resolver = customResolver
		}
	}

	if a.socksProxy != "" {
		// Embed timeout into the URI so h12.io/socks honors it at dial time.
		// socksDialWithClear strips the deadline that the SOCKS5 handshake
		// leaves on the connection, so long-running reads (paged LDAP
		// searches, large SMB/RPC transfers) are not killed by it.
		dialer.socksDial = socksDialWithClear(appendSocksTimeout(a.socksProxy, timeout))
	}

	return dialer
}

// appendSocksTimeout injects ?timeout=<dur> into a SOCKS URI when the user
// has not specified one. h12.io/socks reads this query parameter to bound
// the proxy handshake.
func appendSocksTimeout(uri string, timeout time.Duration) string {
	if timeout <= 0 {
		return uri
	}
	if strings.Contains(uri, "timeout=") {
		return uri
	}
	sep := "?"
	if strings.Contains(uri, "?") {
		sep = "&"
	}
	return fmt.Sprintf("%s%stimeout=%s", uri, sep, timeout)
}

// socksDialWithClear wraps a SOCKS dial function to strip any residual
// Read/Write deadline left on the connection by the SOCKS5 handshake.
// h12.io/socks v1.0.3 clears deadlines on the SOCKS4 path but forgets to
// do so on the SOCKS5 path, which causes i/o timeouts on long-running
// LDAP paged searches that exceed the handshake timeout.
func socksDialWithClear(uri string) func(network, address string) (net.Conn, error) {
	inner := socks.Dial(uri)
	return func(network, address string) (net.Conn, error) {
		c, err := inner(network, address)
		if err != nil {
			return nil, err
		}
		_ = c.SetDeadline(time.Time{})
		return c, nil
	}
}

func (a *CredentialMgr) Resolver() *net.Resolver {
	if a.credential != nil && a.credential.Resolver != nil {
		if customResolver, ok := a.credential.Resolver.(*CustomResolver); ok {
			return customResolver.resolver
		}
	}

	return nil
}

func (a *CredentialMgr) NewTarget(protocol string, targetHost string) *adauth.Target {
	t := adauth.NewTarget(protocol, targetHost)
	t.Resolver = a.credential.Resolver
	t.UseKerberos = a.useKerberos
	return t
}

// ParseCredential determines the authentication method based on provided options
// and returns a preliminary credential. It supports the following methods:
// [Via Kerberos]
// - User + Password
// - User + NTHash
// - User + AESKey
// - User + Certificate (PKINIT / Kerberos)
// ==> Certificate is either PFX or PEM/KEY pair
// - User + CCache
// ==> CCache is either from KRB5CCNAME or --ccache
// [Via regular methods]
// - User + Certificate (SChannel for LDAP, for RPC only PKINIT is possible)
// - User + Password (NTLM)
// - User + NTHash (NTLM)
// - Anonymous (LDAP only)
func ParseCredential(opts *adauth.Options, isEmptyPassword bool) (string, *CredentialMgr, error) {
	if opts == nil {
		return "", nil, fmt.Errorf("invalid options")
	}

	var method string

	creds := new(adauth.Credential)
	domain, username := splitUserIntoDomainAndUsername(opts.User)

	creds.Username = username
	creds.Domain = domain

	if isEmptyPassword {
		if username == "" {
			method = "Anonymous"
		} else {
			method = "Password"
		}

		creds.PasswordIsEmtpyString = true
	} else if username != "" && opts.Password != "" {
		method = "Password"
		creds.Password = opts.Password
	} else if username != "" && opts.NTHash != "" {
		method = "NTHash"

		ntHash := cleanNTHash(opts.NTHash)
		ntHashBytes, err := hex.DecodeString(ntHash)
		if err != nil {
			return "", nil, fmt.Errorf("invalid NT hash: parse hex: %w", err)
		} else if len(ntHashBytes) != 16 {
			return "", nil, fmt.Errorf("invalid NT hash: %d bytes instead of 16", len(ntHashBytes))
		}

		creds.NTHash = ntHash
	} else if username != "" && opts.AESKey != "" {
		// AES key authentication requires Kerberos, auto-enable if not set
		if !opts.ForceKerberos {
			opts.ForceKerberos = true
		}
		method = "AESKey"

		aesKeyBytes, err := hex.DecodeString(opts.AESKey)
		if err != nil {
			return "", nil, fmt.Errorf("invalid AES key format: %w", err)
		} else if len(aesKeyBytes) != 16 && len(aesKeyBytes) != 32 {
			return "", nil, fmt.Errorf("invalid AES key: %d bytes instead of 16 or 32", len(aesKeyBytes))
		}

		creds.AESKey = opts.AESKey
	} else if opts.PFXFileName != "" {
		method = "CertPFX"

		cert, key, caCerts, err := readPFX(opts.PFXFileName, opts.PFXPassword)
		if err != nil {
			return "", nil, err
		}

		creds.ClientCert = cert
		creds.ClientCertKey = key
		creds.CACerts = caCerts
	} else if opts.PEMCertFileName != "" && opts.PEMKeyFileName != "" {
		method = "CertPEM"

		cert, key, err := readPEMCertAndKey(opts.PEMCertFileName, opts.PEMKeyFileName)
		if err != nil {
			return "", nil, err
		}

		creds.ClientCert = cert
		creds.ClientCertKey = key
	} else if opts.CCache != "" || os.Getenv("KRB5CCNAME") != "" {
		// Ticket authentication requires Kerberos, auto-enable if not set
		if !opts.ForceKerberos {
			opts.ForceKerberos = true
		}
		method = "Ticket"

		ccacheFile := os.Getenv("KRB5CCNAME")
		if ccacheFile == "" {
			ccacheFile = opts.CCache
		}

		s, err := os.Stat(ccacheFile)
		if err != nil {
			return "", nil, fmt.Errorf("stat ccache path: %w", err)
		} else if s.IsDir() {
			return "", nil, fmt.Errorf("ccache path is a directory: %s", opts.CCache)
		}

		creds.CCache = ccacheFile
	}

	creds.Resolver = opts.Resolver
	auth := NewCredentialMgr(creds, opts.ForceKerberos)

	return method, auth, nil
}

func readPEMCertAndKey(certFileName string, certKeyFileName string) (*x509.Certificate, any, error) {
	certData, err := os.ReadFile(certFileName)
	if err != nil {
		return nil, nil, fmt.Errorf("read cert file: %w", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, nil, fmt.Errorf("could not PEM-decode certificate")
	}

	if block.Type != "" && !strings.Contains(strings.ToLower(block.Type), "certificate") {
		return nil, nil, fmt.Errorf("unexpected block type for certificate: %q", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}

	certKeyData, err := os.ReadFile(certKeyFileName)
	if err != nil {
		return nil, nil, fmt.Errorf("read cert key file: %w", err)
	}

	block, _ = pem.Decode(certKeyData)
	if block == nil {
		return nil, nil, fmt.Errorf("could not PEM-decode certificate key")
	}

	if block.Type != "" && !strings.Contains(strings.ToLower(block.Type), "key") {
		return nil, nil, fmt.Errorf("unexpected block type for key: %q", block.Type)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, pkcs1Err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if pkcs1Err == nil {
			return cert, key, nil
		}

		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}

	return cert, key, nil
}

func readPFX(fileName string, password string) (*x509.Certificate, any, []*x509.Certificate, error) {
	pfxData, err := os.ReadFile(fileName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read PFX: %w", err)
	}

	key, cert, caCerts, err := adauth.DecodePFX(pfxData, password)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode PFX: %w", err)
	}

	return cert, key, caCerts, nil
}

// From https://github.com/RedTeamPentesting/adauth/blob/main/credentials.go#L237
func splitUserIntoDomainAndUsername(user string) (domain string, username string) {
	switch {
	case strings.Contains(user, "@"):
		parts := strings.Split(user, "@")
		if len(parts) >= 2 {
			user := strings.Join(parts[0:len(parts)-1], "@")
			domain := parts[len(parts)-1]
			return domain, user
		}

		return "", user
	case strings.Contains(user, `\`):
		parts := strings.Split(user, `\`)
		if len(parts) == 2 {
			return parts[0], parts[1]
		}

		return "", user
	case strings.Contains(user, "/"):
		parts := strings.Split(user, "/")
		if len(parts) == 2 {
			return parts[0], parts[1]
		}

		return "", user
	default:
		return "", user
	}
}

func cleanNTHash(h string) string {
	if !strings.Contains(h, ":") {
		return h
	}

	parts := strings.Split(h, ":")
	if len(parts) != 2 {
		return h
	}

	return parts[1]
}
