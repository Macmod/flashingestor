package bloodhound

import (
	"context"
	"strings"
	"time"

	"github.com/Macmod/flashingestor/config"
)

const (
	// Computer availability error messages
	ErrorNonWindowsOS = "NonWindowsOS"
	ErrorNotActive    = "NotActive"
	ErrorPortNotOpen  = "PortNotOpen"

	// Default thresholds
	DefaultPasswordAgeThreshold = 60 * 24 * time.Hour // 60 days
	SMBPort                     = 445
)

// passwordAgeCheck checks if a computer is active based on password last set and last logon timestamp
// Returns true if either pwdLastSet or lastLogonTimestamp is within the threshold (60 days by default)
func passwordAgeCheck(pwdLastSet, lastLogonTimestamp int64, threshold time.Duration) bool {
	if threshold == 0 {
		threshold = DefaultPasswordAgeThreshold
	}

	now := time.Now()
	cutoff := now.Add(-threshold).Unix()

	// Check pwdLastSet
	if pwdLastSet > 0 && pwdLastSet >= cutoff {
		return true
	}

	// Check lastLogonTimestamp
	if lastLogonTimestamp > 0 && lastLogonTimestamp >= cutoff {
		return true
	}

	return false
}

// checkInstantAvailability runs instant (non-network) availability checks.
// Returns true if all enabled instant checks pass.
func checkInstantAvailability(
	operatingSystem string,
	pwdLastSet int64,
	lastLogonTimestamp int64,
	enabledChecks map[string]bool,
) (bool, string) {
	// Check if operating system is Windows
	if enabledChecks["windows_os"] {
		if operatingSystem != "" && !strings.HasPrefix(strings.ToLower(operatingSystem), "windows") {
			return false, ErrorNonWindowsOS
		}
	}

	// Check if computer is active based on password/logon timestamps
	if enabledChecks["password_age"] {
		if !passwordAgeCheck(pwdLastSet, lastLogonTimestamp, DefaultPasswordAgeThreshold) {
			return false, ErrorNotActive
		}
	}

	return true, ""
}

// checkPortAvailability checks if SMB port 445 is open.
func (rc *RemoteCollector) smbPortCheck(
	ctx context.Context,
	computerName string,
) (bool, string) {
	dialer := rc.auth.Dialer(config.PORTCHECK_TIMEOUT)
	if open, err := checkPortOpen(ctx, dialer, computerName, SMBPort); !open || err != nil {
		return false, ErrorPortNotOpen
	}
	return true, ""
}