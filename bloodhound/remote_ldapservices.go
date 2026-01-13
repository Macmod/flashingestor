package bloodhound

import (
	"context"
	"net"
	"strconv"
	"strings"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/config"
	"github.com/RedTeamPentesting/adauth/ldapauth"
)

// collectLdapServices checks LDAP/LDAPS port availability and channel binding requirements on a target system
func (rc *RemoteCollector) collectLdapServices(ctx context.Context, targetHost string) builder.LdapServicesResult {
	result := builder.LdapServicesResult{}

	dialer := rc.auth.Dialer(config.PORTCHECK_TIMEOUT)

	// Check if LDAP port 389 is available
	hasLdap, _ := checkPortOpen(ctx, dialer, targetHost, 389)
	result.HasLdap = hasLdap

	// Check if LDAPS port 636 is available
	hasLdaps, _ := checkPortOpen(ctx, dialer, targetHost, 636)
	result.HasLdaps = hasLdaps

	if result.HasLdap {
		result.IsSigningRequired.Collected = true

		resultCheck := checkSigningRequired(ctx, targetHost, rc.auth)
		result.IsSigningRequired.Result = &resultCheck
	}

	if result.HasLdaps {
		result.IsChannelBindingRequired.Collected = true

		resultCheck := checkChannelBindingRequired(ctx, targetHost, rc.auth)
		result.IsChannelBindingRequired.Result = &resultCheck
	}

	return result
}

// checkPortOpen attempts to connect to a port with a timeout
func checkPortOpen(ctx context.Context, dialer *net.Dialer, host string, port int) (bool, error) {
	address := net.JoinHostPort(host, strconv.Itoa(port))

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	return true, nil
}

func checkChannelBindingRequired(ctx context.Context, host string, auth *config.CredentialMgr) bool {
	options := ldapauth.Options{
		Scheme:                "ldaps",
		Timeout:               config.PORTCHECK_TIMEOUT,
		DisableChannelBinding: true,
		KerberosDialer:        auth.Dialer(config.KERBEROS_TIMEOUT),
		LDAPDialer:            auth.Dialer(config.PORTCHECK_TIMEOUT),
	}

	creds := auth.Creds()
	target := auth.NewTarget("ldaps", host)

	// Test the connection
	conn, err := ldapauth.ConnectTo(ctx, creds, target, &options)
	if err != nil {
		// Error code for missing channel bindings
		if strings.Contains(err.Error(), "data 80090346") {
			return true
		}
		return false
	}
	defer conn.Close()

	return false
}

func checkSigningRequired(ctx context.Context, host string, auth *config.CredentialMgr) bool {
	// Currently there's no option to disable signing
	// as it's [not implemented yet] in adauth
	// [In theory] we just have to try to connect normally
	options := ldapauth.Options{
		Scheme:         "ldap",
		Timeout:        config.PORTCHECK_TIMEOUT,
		KerberosDialer: auth.Dialer(config.KERBEROS_TIMEOUT),
		LDAPDialer:     auth.Dialer(config.PORTCHECK_TIMEOUT),
	}

	creds := auth.Creds()
	target := auth.NewTarget("ldap", host)

	// Test the connection
	conn, err := ldapauth.ConnectTo(ctx, creds, target, &options)
	if err != nil {
		if strings.Contains(err.Error(), "Strong Auth Required") {
			return true
		}
		return false
	}
	defer conn.Close()

	return false
}
