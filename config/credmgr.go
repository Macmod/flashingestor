package config

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/RedTeamPentesting/adauth"
)

type CredentialMgr struct {
	credential  *adauth.Credential
	useKerberos bool
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

func (a *CredentialMgr) Kerberos() bool {
	return a.useKerberos
}

func (a *CredentialMgr) Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout:  timeout,
		Resolver: a.credential.Resolver.(*net.Resolver),
	}
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
// - User + Certificate (depends)
// - User + Password (NTLM)
// - User + NTHash (NTLM)
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
	} else if opts.ForceKerberos && username != "" && opts.AESKey != "" {
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
	} else if opts.ForceKerberos && (opts.CCache != "" || os.Getenv("KRB5CCNAME") != "") {
		method = "Ticket"

		ccacheFile := os.Getenv("KRB5CCNAME")
		if ccacheFile == "" {
			ccacheFile = opts.CCache
		}

		s, err := os.Stat(ccacheFile)
		if err != nil {
			return "", nil, fmt.Errorf("stat CCache path: %w", err)
		} else if s.IsDir() {
			return "", nil, fmt.Errorf("CCache path is a directory: %s", opts.CCache)
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
		if len(parts) == 2 {
			return parts[1], parts[0]
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
