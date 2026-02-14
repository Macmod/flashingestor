// Package config handles command-line flags, authentication, and runtime
// configuration for flashingestor.
package config

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/RedTeamPentesting/adauth"
	"github.com/RedTeamPentesting/adauth/ldapauth"
	"github.com/spf13/pflag"
)

// Config holds all application configuration
type Config struct {
	DomainController      string
	OutputDir             string
	LogFile               string
	RemoteWorkers         int
	RemoteComputerTimeout time.Duration
	RemoteMethodTimeout   time.Duration
	CustomDns             string
	DnsTcp                bool
	ConfigPath            string
	PprofEnabled          bool
	VerbosityLevel        int
	LdapAuthOptions       *ldapauth.Options
	RuntimeOptions        *RuntimeOptions

	IngestAuth       *CredentialMgr
	RemoteAuth       *CredentialMgr
	ChosenAuthIngest string
	ChosenAuthRemote string
	Resolver         *CustomResolver
}

const DEFAULT_REMOTE_METHOD_TIMEOUT = 4 * time.Second
const DEFAULT_REMOTE_COMPUTER_TIMEOUT = 10 * time.Second
const DEFAULT_REMOTE_WORKERS = 50
const DEFAULT_LDAP_TIMEOUT = 30 * time.Second
const DEFAULT_LDAP_SCHEME = "ldaps"

// Timeout constants for various network operations
const PORTCHECK_TIMEOUT = 2 * time.Second   // Generic timeout for port checking
const NETBIOS_TIMEOUT = 2 * time.Second     // Timeout for NetBIOS
const HTTP_TIMEOUT = 3 * time.Second        // Timeout for HTTP
const DCERPC_EPM_TIMEOUT = 2 * time.Second  // Timeout for DCE/RPC endpoint mapper
const KERBEROS_TIMEOUT = 2 * time.Second    // Timeout for Kerberos
const SMB_TIMEOUT = 2 * time.Second         // Timeout for SMB
const DNS_DIAL_TIMEOUT = 5 * time.Second    // Timeout for dialing to DNS server
const DNS_LOOKUP_TIMEOUT = 10 * time.Second // Timeout for DNS lookups

// DialerWithResolver implements custom LDAP dialing with DNS resolver override.
// TODO: Review if there's a better way (shouldn't ConnectTo respect my specified Resolver?)
type DialerWithResolver struct {
	Resolver *CustomResolver
}

// DialContext resolves the address using the custom resolver and dials using TCP.
func (d *DialerWithResolver) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Use your resolver to resolve the address first
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	ips, err := d.Resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}

	// Try each IP until connection succeeds
	for _, ip := range ips {
		conn, err := net.DialTimeout(network, net.JoinHostPort(ip, port), DEFAULT_LDAP_TIMEOUT)
		if err == nil {
			return conn, nil
		}
	}

	return nil, fmt.Errorf("failed to connect to any IP for %s", addr)
}

// Dial implements the Dialer interface with a default context timeout.
func (d *DialerWithResolver) Dial(network, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DNS_LOOKUP_TIMEOUT)
	defer cancel()
	return d.DialContext(ctx, network, addr)
}

// ParseFlags parses command line flags and returns a configuration instance
func ParseFlags() (*Config, error) {
	var err error
	var showVersion bool

	config := &Config{
		LdapAuthOptions: &ldapauth.Options{},
	}

	// Version flag
	pflag.BoolVar(&showVersion, "version", false, "Show version information and exit")

	// Verbosity flag (can be repeated: -v, -vv)
	var verbosity int
	pflag.CountVarP(&verbosity, "verbose", "v", "Increase verbosity level (can be used multiple times: -v for verbose, -vv for debug)")

	// Basic settings
	pflag.StringVar(&config.OutputDir, "outdir", "./output", "Directory to store results")
	pflag.StringVar(&config.LogFile, "log", "", "Path to log file (optional, logs will be written to both file and UI)")
	pflag.StringVar(&config.ConfigPath, "config", "config.yaml", "Path to YAML config file (optional)")
	pflag.StringVar(&config.CustomDns, "dns", "", "Custom DNS resolver to use")
	pflag.BoolVar(&config.DnsTcp, "dns-tcp", false, "Use DNS over TCP instead of UDP")
	pflag.BoolVar(&config.PprofEnabled, "pprof", false, "Enable pprof profiling server on http://localhost:6060")
	pflag.StringVar(&config.DomainController, "dc", "", "Domain controller to use")
	pflag.IntVarP(&config.RemoteWorkers, "remote-workers", "w", DEFAULT_REMOTE_WORKERS, "Number of concurrent workers for remote collection")
	pflag.DurationVar(&config.RemoteComputerTimeout, "computer-timeout", DEFAULT_REMOTE_COMPUTER_TIMEOUT, "Timeout per computer for remote collection")
	pflag.DurationVar(&config.RemoteMethodTimeout, "method-timeout", DEFAULT_REMOTE_METHOD_TIMEOUT, "Timeout per method of remote collection")

	// Register adauth flags for ingestion
	standardAuthOptions := &adauth.Options{}
	registerIngestionAuthFlags(standardAuthOptions, pflag.CommandLine)

	// Register remote-prefixed flags for remote collection
	remoteAuthOptions := &adauth.Options{}
	registerRemoteAuthFlags(remoteAuthOptions, pflag.CommandLine)

	// Register flags related to LDAP connection
	registerLdapFlags(config.LdapAuthOptions, pflag.CommandLine)

	pflag.Parse()

	// Set verbosity from command line
	if verbosity > 0 {
		config.VerbosityLevel = verbosity
	}

	// Check for version flag first
	if showVersion {
		// Return a special error that signals version was requested
		return nil, fmt.Errorf("VERSION_REQUESTED")
	}

	// Setup DNS resolver
	var resolver *CustomResolver
	if config.CustomDns != "" {
		var err error
		resolver, err = setupDNSResolver(config.CustomDns, config.DnsTcp)
		if err != nil {
			return nil, fmt.Errorf("failed to setup DNS resolver: %w", err)
		}
	} else {
		// Wrap default resolver with caching
		resolver = &CustomResolver{
			resolver: net.DefaultResolver,
			cache:    newDNSCache(),
		}
	}
	config.Resolver = resolver

	// Set resolver on auth options after it's been configured
	standardAuthOptions.Resolver = resolver
	remoteAuthOptions.Resolver = resolver

	// Load runtime options from config file or use defaults
	config.RuntimeOptions, err = LoadOptions(config.ConfigPath)
	if err != nil {
		return nil, err
	}

	// Used for LDAP connections
	config.LdapAuthOptions.LDAPDialer = &DialerWithResolver{
		Resolver: resolver,
	}

	config.LdapAuthOptions.KerberosDialer = &DialerWithResolver{
		Resolver: resolver,
	}

	isEmptyPassword := standardAuthOptions.Password == "" && pflag.CommandLine.Changed("password")
	chosenAuthIngest, ingestAuth, err := ParseCredential(standardAuthOptions, isEmptyPassword)
	if err != nil {
		return nil, err
	}
	if ingestAuth != nil {
		ingestAuth.SetDC(config.DomainController)
		config.IngestAuth = ingestAuth
	}

	// Password should be required for remote collection
	// that's why "isEmptyPassword" is always false here
	chosenAuthRemote, remoteAuth, err := ParseCredential(remoteAuthOptions, false)
	if err != nil {
		return nil, err
	}
	if chosenAuthRemote != "" && remoteAuth != nil {
		// Not sure if it's needed to set the DC here,
		// setting just in case (maybe it's needed for kerberos?)
		remoteAuth.SetDC(config.DomainController)
		config.RemoteAuth = remoteAuth
	} else {
		config.RemoteAuth = ingestAuth
		chosenAuthRemote = chosenAuthIngest
	}

	config.ChosenAuthIngest = chosenAuthIngest
	config.ChosenAuthRemote = chosenAuthRemote

	return config, nil
}

// registerIngestionAuthFlags registers authentication flags for LDAP ingestion
func registerIngestionAuthFlags(opts *adauth.Options, flagset *pflag.FlagSet) {
	flagset.StringVarP(&opts.User, "user", "u", "", "Username for ingestion (with domain) in one of the following formats: UPN, domain\\user, domain/user or user")
	flagset.StringVarP(&opts.Password, "password", "p", "", "Password for ingestion")
	flagset.StringVarP(&opts.NTHash, "nt-hash", "H", "", "NT hash for ingestion")
	flagset.StringVar(&opts.AESKey, "aes-key", "", "AES key for ingestion")
	flagset.StringVar(&opts.CCache, "ccache", "", "Path to CCache file for ingestion")
	flagset.BoolVarP(&opts.ForceKerberos, "kerberos", "k", false, "Force Kerberos authentication for ingestion")
	flagset.StringVar(&opts.PFXFileName, "pfx", "", "PFX file for ingestion")
	flagset.StringVar(&opts.PFXPassword, "pfx-password", "", "Password for PFX file for ingestion")
	flagset.StringVar(&opts.PEMCertFileName, "cert", "", "PEM certificate file for ingestion")
	flagset.StringVar(&opts.PEMKeyFileName, "key", "", "PEM key file for ingestion")
}

// registerRemoteAuthFlags registers remote-prefixed authentication flags for remote collection
func registerRemoteAuthFlags(opts *adauth.Options, flagset *pflag.FlagSet) {
	flagset.StringVar(&opts.User, "remote-user", "", "Username for remote collection (with domain) in one of the following formats: UPN, domain\\user, domain/user or user")
	flagset.StringVar(&opts.Password, "remote-password", "", "Password for remote collection")
	flagset.StringVar(&opts.NTHash, "remote-nthash", "", "NT hash for remote collection")
	flagset.StringVar(&opts.AESKey, "remote-aeskey", "", "AES key for remote collection")
	flagset.StringVar(&opts.CCache, "remote-ccache", "", "Path to CCache file for remote collection")
	flagset.BoolVar(&opts.ForceKerberos, "remote-kerberos", false, "Force Kerberos authentication for remote collection")
	flagset.StringVar(&opts.PFXFileName, "remote-pfx", "", "PFX file for remote collection")
	flagset.StringVar(&opts.PFXPassword, "remote-pfx-password", "", "Password for PFX file for remote collection")
	flagset.StringVar(&opts.PEMCertFileName, "remote-cert", "", "PEM certificate file for remote collection")
	flagset.StringVar(&opts.PEMKeyFileName, "remote-key", "", "PEM key file for remote collection")
}

func registerLdapFlags(opts *ldapauth.Options, flagset *pflag.FlagSet) {
	flagset.StringVar(&opts.Scheme, "scheme", DEFAULT_LDAP_SCHEME, "Scheme (ldap or ldaps)")
	flagset.DurationVar(&opts.Timeout, "timeout", DEFAULT_LDAP_TIMEOUT, "LDAP connection timeout")
	flagset.BoolVar(&opts.Verify, "verify", false, "Verify LDAP TLS certificate")
	flagset.BoolVar(&opts.StartTLS, "start-tls", false, "Negotiate StartTLS before authenticating on regular LDAP connection")
	//flagset.BoolVar(&opts.SimpleBind, "simple-bind", false, "Use simple bind instead of NTLM/Kerberos/mTLS (password required)")
}

// setupDNSResolver creates and configures a custom DNS resolver with caching.
func setupDNSResolver(customDNS string, useTCP bool) (*CustomResolver, error) {
	ip := net.ParseIP(customDNS)
	if ip == nil {
		return nil, fmt.Errorf("invalid custom DNS resolver IP address: '%s'", customDNS)
	}

	dnsDialer := net.Dialer{
		Timeout: DNS_DIAL_TIMEOUT,
	}

	baseResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if useTCP {
				return dnsDialer.DialContext(ctx, "tcp", customDNS+":53")
			}
			return dnsDialer.DialContext(ctx, "udp", customDNS+":53")
		},
	}

	// Wrap with caching resolver
	customResolver := &CustomResolver{
		resolver: baseResolver,
		cache:    newDNSCache(),
	}

	return customResolver, nil
}
