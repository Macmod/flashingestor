package bloodhound

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/config"
)

// CollectionTarget identifies a computer for remote data collection.
type CollectionTarget struct {
	SID                string
	DNSHostName        string
	SamName            string
	IsDC               bool
	Domain             string
	OperatingSystem    string
	PwdLastSet         int64
	LastLogonTimestamp int64
}

// RemoteCollectionResult holds all data collected remotely from a computer.
type RemoteCollectionResult struct {
	SID                   string
	LocalGroups           []builder.LocalGroupAPIResult
	Sessions              builder.SessionAPIResult
	PrivilegedSessions    builder.SessionAPIResult
	RegistrySessions      builder.SessionAPIResult
	DCRegistryData        builder.DCRegistryData
	NTLMRegistryData      builder.NTLMRegistryData
	UserRights            []builder.UserRightsAPIResult
	IsWebClientRunning    builder.IsWebClientRunningAPIResult
	LdapServices          builder.LdapServicesResult
	SMBInfo               *builder.SMBInfoAPIResult
	Status                *builder.ComputerStatus
	AttemptedMethodsCount int `msgpack:"-"` // Not serialized (only used for progress tracking)
}

// Small helper as computer results include many fields to update
func (rcr *RemoteCollectionResult) StoreInComputer(computer *builder.Computer) {
	computer.LocalGroups = rcr.LocalGroups
	computer.PrivilegedSessions = rcr.PrivilegedSessions
	computer.Sessions = rcr.Sessions
	computer.RegistrySessions = rcr.RegistrySessions
	computer.NTLMRegistryData = rcr.NTLMRegistryData
	computer.UserRights = rcr.UserRights
	computer.IsWebClientRunning = rcr.IsWebClientRunning
	computer.SMBInfo = rcr.SMBInfo
	computer.Status = rcr.Status

	if computer.IsDC {
		computer.DCRegistryData = rcr.DCRegistryData

		if rcr.LdapServices.HasLdap {
			hasLdap := true
			computer.Properties.LdapAvailable = &hasLdap
		}
		if rcr.LdapServices.HasLdaps {
			hasLdaps := true
			computer.Properties.LdapsAvailable = &hasLdaps
		}
		if rcr.LdapServices.IsChannelBindingRequired.Collected {
			computer.Properties.LdapsEpa = rcr.LdapServices.IsChannelBindingRequired.Result
		}
		if rcr.LdapServices.IsSigningRequired.Collected {
			computer.Properties.LdapSigning = rcr.LdapServices.IsSigningRequired.Result
		}
	}
}

// CountAttemptedMethods returns the number of collection methods that were attempted (ran, whether successful or not)
func (rcr *RemoteCollectionResult) CountAttemptedMethods() int {
	return rcr.AttemptedMethodsCount
}

// GetTotalMethods returns the total number of collection methods enabled for this target
func (rcr *RemoteCollectionResult) GetTotalMethods(runtimeOptions *config.RuntimeOptions, isDC bool) int {
	total := 0

	// Count all enabled methods
	if runtimeOptions.IsMethodEnabled("regsessions") {
		total++
	}
	if runtimeOptions.IsMethodEnabled("ntlmregistry") {
		total++
	}
	if runtimeOptions.IsMethodEnabled("smbinfo") {
		total++
	}
	if runtimeOptions.IsMethodEnabled("localgroups") {
		total++
	}
	if runtimeOptions.IsMethodEnabled("userrights") {
		total++
	}
	if runtimeOptions.IsMethodEnabled("loggedon") {
		total++
	}
	if runtimeOptions.IsMethodEnabled("sessions") {
		total++
	}
	if runtimeOptions.IsMethodEnabled("webclient") {
		total++
	}

	// DC-only methods
	if isDC {
		if runtimeOptions.IsMethodEnabled("dcregistry") {
			total++
		}
		if runtimeOptions.IsMethodEnabled("ldapservices") {
			total++
		}
	}

	return total
}

// CollectRemoteComputerWithContext wraps CollectRemoteComputer with hard timeout enforcement.
// Returns the result and a boolean indicating if the collection completed successfully (true = success, false = aborted).
// On timeout, returns partial results collected before the timeout.
func (rc *RemoteCollector) CollectRemoteComputerWithContext(ctx context.Context, target CollectionTarget) (RemoteCollectionResult, bool) {
	result := RemoteCollectionResult{SID: target.SID}
	done := make(chan struct{})
	var mu sync.Mutex

	go func() {
		defer close(done)
		skipAuth := rc.noCrossDomain && !strings.EqualFold(target.Domain, rc.auth.Creds().Domain)
		if skipAuth {
			rc.logger.Log1("🦘 [yellow][%s[] Skipped Computer (cross-domain auth disabled)[-]", target.DNSHostName)
			return
		}

		rc.CollectRemoteComputer(ctx, target, &result, &mu)
	}()

	select {
	case <-done:
		return result, true
	case <-ctx.Done():
		// Lock to safely read partial results while worker may still be writing
		mu.Lock()
		snapshot := result
		mu.Unlock()
		return snapshot, false
	}
}

func (rc *RemoteCollector) CollectRemoteComputer(ctx context.Context, target CollectionTarget, result *RemoteCollectionResult, mu *sync.Mutex) {
	totalStart := time.Now()
	rpcManager := NewRPCManager(target.DNSHostName, rc.auth)
	defer rpcManager.Close()

	methodTimes := rpcManager.GetMethodTimes()
	var stepStart time.Time

	// Uses Winreg RPC
	if rc.RuntimeOptions.IsMethodEnabled("regsessions") {
		if ctx.Err() != nil {
			return
		}
		stepStart = time.Now()
		regSessions := rc.collectRegistrySessions(ctx, target.SID, rpcManager)
		methodTimes["regsessions"] = time.Since(stepStart)
		mu.Lock()
		result.RegistrySessions = regSessions
		result.AttemptedMethodsCount++
		mu.Unlock()
	}

	// Uses Winreg RPC
	if rc.RuntimeOptions.IsMethodEnabled("ntlmregistry") {
		if ctx.Err() != nil {
			return
		}
		stepStart = time.Now()
		ntlmData := rc.collectNTLMRegistryData(ctx, rpcManager)
		methodTimes["ntlmregistry"] = time.Since(stepStart)
		mu.Lock()
		result.NTLMRegistryData = ntlmData
		result.AttemptedMethodsCount++
		mu.Unlock()
	}

	// Uses Winreg RPC
	if target.IsDC && rc.RuntimeOptions.IsMethodEnabled("dcregistry") {
		if ctx.Err() != nil {
			return
		}
		stepStart = time.Now()
		dcRegData := rc.collectDCRegistryData(ctx, rpcManager)
		methodTimes["dcregistry"] = time.Since(stepStart)
		mu.Lock()
		result.DCRegistryData = dcRegData
		result.AttemptedMethodsCount++
		mu.Unlock()
	}

	// Uses Winreg RPC
	// (pending checks with raw SMB negotiation)
	if rc.RuntimeOptions.IsMethodEnabled("smbinfo") {
		if ctx.Err() != nil {
			return
		}
		stepStart = time.Now()
		smbInfo := rc.collectSmbInfo(ctx, rpcManager)
		methodTimes["smbinfo"] = time.Since(stepStart)
		mu.Lock()
		result.SMBInfo = &smbInfo
		result.AttemptedMethodsCount++
		mu.Unlock()
	}

	// Uses Samr RPC & Lsat RPC
	if rc.RuntimeOptions.IsMethodEnabled("localgroups") {
		if ctx.Err() != nil {
			return
		}
		stepStart = time.Now()
		stepCtx, cancel := context.WithTimeout(ctx, rc.RemoteMethodTimeout)
		localGroups := rc.collectLocalGroups(stepCtx, target.SID, target.IsDC, target.Domain, rpcManager)
		cancel()
		methodTimes["localgroups"] = time.Since(stepStart)
		mu.Lock()
		result.LocalGroups = localGroups
		result.AttemptedMethodsCount++
		mu.Unlock()
	}

	// Uses Lsad RPC & Lsat RPC
	if rc.RuntimeOptions.IsMethodEnabled("userrights") {
		if ctx.Err() != nil {
			return
		}
		stepStart = time.Now()
		stepCtx, cancel := context.WithTimeout(ctx, rc.RemoteMethodTimeout)
		userRights := rc.collectUserRights(stepCtx, target.SID, target.IsDC, target.Domain, rpcManager)
		cancel()
		methodTimes["userrights"] = time.Since(stepStart)
		mu.Lock()
		result.UserRights = userRights
		result.AttemptedMethodsCount++
		mu.Unlock()
	}

	// Uses WksSvc RPC
	if rc.RuntimeOptions.IsMethodEnabled("loggedon") {
		if ctx.Err() != nil {
			return
		}
		stepStart = time.Now()
		stepCtx, cancel := context.WithTimeout(ctx, rc.RemoteMethodTimeout)
		privSessions := rc.collectPrivilegedSessions(stepCtx, target.SamName, target.SID, rpcManager)
		cancel()
		methodTimes["loggedon"] = time.Since(stepStart)
		mu.Lock()
		result.PrivilegedSessions = privSessions
		result.AttemptedMethodsCount++
		mu.Unlock()
	}

	// Uses SrvSvc RPC
	if rc.RuntimeOptions.IsMethodEnabled("sessions") {
		if ctx.Err() != nil {
			return
		}
		stepStart = time.Now()
		stepCtx, cancel := context.WithTimeout(ctx, rc.RemoteMethodTimeout)
		sessions := rc.collectSessions(stepCtx, target.SID, target.Domain, rpcManager)
		cancel()
		methodTimes["sessions"] = time.Since(stepStart)
		mu.Lock()
		result.Sessions = sessions
		result.AttemptedMethodsCount++
		mu.Unlock()
	}

	// Uses SMB to check "DAV RPC Service" named pipe
	if rc.RuntimeOptions.IsMethodEnabled("webclient") {
		if ctx.Err() != nil {
			return
		}
		stepStart = time.Now()
		stepCtx, cancel := context.WithTimeout(ctx, rc.RemoteMethodTimeout)
		webClient := rc.collectIsWebClientRunning(stepCtx, target.DNSHostName)
		cancel()
		methodTimes["webclient"] = time.Since(stepStart)
		mu.Lock()
		result.IsWebClientRunning = webClient
		result.AttemptedMethodsCount++
		mu.Unlock()
	}

	// Just port checks & LDAP/LDAPS auth
	if target.IsDC && rc.RuntimeOptions.IsMethodEnabled("ldapservices") {
		if ctx.Err() != nil {
			return
		}
		stepStart = time.Now()
		stepCtx, cancel := context.WithTimeout(ctx, rc.RemoteMethodTimeout)
		ldapServices := rc.collectLdapServices(stepCtx, target.DNSHostName)
		cancel()
		methodTimes["ldapservices"] = time.Since(stepStart)
		mu.Lock()
		result.LdapServices = ldapServices
		result.AttemptedMethodsCount++
		mu.Unlock()
	}

	totalTime := time.Since(totalStart)
	if len(methodTimes) > 0 {
		rc.logger.Log2("💻 [%s[] Collected in %s: %s", target.DNSHostName, totalTime.Round(time.Millisecond), formatMethodTimes(methodTimes))
	} else {
		rc.logger.Log2("💻 [%s[] Collected in %s", target.DNSHostName, totalTime.Round(time.Millisecond))
	}

	return
}
