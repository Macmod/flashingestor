package bloodhound

import (
	"context"
	"time"

	"github.com/Macmod/flashingestor/bloodhound/builder"
)

// CollectionTarget identifies a computer for remote data collection.
type CollectionTarget struct {
	SID                string
	DNSHostName        string
	SamName            string
	IPAddress          string
	IsDC               bool
	Domain             string
	OperatingSystem    string
	PwdLastSet         int64
	LastLogonTimestamp int64
}

// RemoteCollectionResult holds all data collected remotely from a computer.
type RemoteCollectionResult struct {
	SID                string                              `json:"SID"`
	LocalGroups        []builder.LocalGroupAPIResult       `json:"LocalGroups"`
	Sessions           builder.SessionAPIResult            `json:"Sessions"`
	PrivilegedSessions builder.SessionAPIResult            `json:"PrivilegedSessions"`
	RegistrySessions   builder.SessionAPIResult            `json:"RegistrySessions"`
	DCRegistryData     builder.DCRegistryData              `json:"DCRegistryData"`
	NTLMRegistryData   builder.NTLMRegistryData            `json:"NTLMRegistryData"`
	UserRights         []builder.UserRightsAPIResult       `json:"UserRights"`
	IsWebClientRunning builder.IsWebClientRunningAPIResult `json:"IsWebClientRunning"`
	LdapServices       builder.LdapServicesResult          `json:"LdapServices"`
	SMBInfo            *builder.SMBInfoAPIResult           `json:"SMBInfo"`
	Status             builder.ComputerStatus              `json:"Status"`
}

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

// CollectRemoteComputerWithContext wraps CollectRemoteComputer with hard timeout enforcement.
func (rc *RemoteCollector) CollectRemoteComputerWithContext(ctx context.Context, target CollectionTarget) RemoteCollectionResult {
	resultCh := make(chan RemoteCollectionResult, 1)
	startTime := time.Now()

	go func() {
		resultCh <- rc.CollectRemoteComputer(target)
	}()

	select {
	case result := <-resultCh:
		return result
	case <-ctx.Done():
		rc.logger.Log1("❌ [red][%s[] Aborted after %v (timeout hit?)[-]", target.DNSHostName, time.Since(startTime).Round(time.Millisecond))
		return RemoteCollectionResult{}
	}
}

func (rc *RemoteCollector) CollectRemoteComputer(target CollectionTarget) RemoteCollectionResult {
	totalStart := time.Now()

	methodTimes := make(map[string]time.Duration)
	result := RemoteCollectionResult{
		SID: target.SID,
	}

	var stepStart time.Time

	// Each method should have its own independent context
	if rc.RuntimeOptions.IsMethodEnabled("localgroups") {
		stepStart = time.Now()
		stepCtx, cancel := context.WithTimeout(context.Background(), rc.RemoteMethodTimeout)
		result.LocalGroups = rc.collectLocalGroups(stepCtx, target.IPAddress, target.DNSHostName, target.SID, target.IsDC, target.Domain)
		cancel()
		methodTimes["localgroups"] = time.Since(stepStart)
	}
	if rc.RuntimeOptions.IsMethodEnabled("loggedon") {
		stepStart = time.Now()
		stepCtx, cancel := context.WithTimeout(context.Background(), rc.RemoteMethodTimeout)
		result.PrivilegedSessions = rc.collectPrivilegedSessions(stepCtx, target.IPAddress, target.SamName, target.SID)
		cancel()
		methodTimes["loggedon"] = time.Since(stepStart)
	}
	if rc.RuntimeOptions.IsMethodEnabled("sessions") {
		stepStart = time.Now()
		stepCtx, cancel := context.WithTimeout(context.Background(), rc.RemoteMethodTimeout)
		result.Sessions = rc.collectSessions(stepCtx, target.IPAddress, target.SID, target.Domain)
		cancel()
		methodTimes["sessions"] = time.Since(stepStart)
	}
	if rc.RuntimeOptions.IsMethodEnabled("regsessions") {
		stepStart = time.Now()
		stepCtx, cancel := context.WithTimeout(context.Background(), rc.RemoteMethodTimeout)
		result.RegistrySessions = rc.collectRegistrySessions(stepCtx, target.IPAddress, target.SID)
		cancel()
		methodTimes["regsessions"] = time.Since(stepStart)
	}
	if rc.RuntimeOptions.IsMethodEnabled("ntlmregistry") {
		stepStart = time.Now()
		stepCtx, cancel := context.WithTimeout(context.Background(), rc.RemoteMethodTimeout)
		result.NTLMRegistryData = rc.collectNTLMRegistryData(stepCtx, target.IPAddress)
		cancel()
		methodTimes["ntlmregistry"] = time.Since(stepStart)
	}
	if rc.RuntimeOptions.IsMethodEnabled("userrights") {
		stepStart = time.Now()
		stepCtx, cancel := context.WithTimeout(context.Background(), rc.RemoteMethodTimeout)
		result.UserRights = rc.collectUserRights(stepCtx, target.IPAddress, target.DNSHostName, target.SID, target.IsDC, target.Domain)
		cancel()
		methodTimes["userrights"] = time.Since(stepStart)
	}
	if rc.RuntimeOptions.IsMethodEnabled("webclient") {
		stepStart = time.Now()
		stepCtx, cancel := context.WithTimeout(context.Background(), rc.RemoteMethodTimeout)
		result.IsWebClientRunning = rc.collectIsWebClientRunning(stepCtx, target.IPAddress)
		cancel()
		methodTimes["webclient"] = time.Since(stepStart)
	}
	if rc.RuntimeOptions.IsMethodEnabled("smbinfo") {
		stepStart = time.Now()
		stepCtx, cancel := context.WithTimeout(context.Background(), rc.RemoteMethodTimeout)
		smbInfo := rc.collectSmbInfo(stepCtx, target.IPAddress)
		result.SMBInfo = &smbInfo
		cancel()
		methodTimes["smbinfo"] = time.Since(stepStart)
	}

	if target.IsDC {
		if rc.RuntimeOptions.IsMethodEnabled("dcregistry") {
			stepStart = time.Now()
			stepCtx, cancel := context.WithTimeout(context.Background(), rc.RemoteMethodTimeout)
			result.DCRegistryData = rc.collectDCRegistryData(stepCtx, target.IPAddress)
			cancel()
			methodTimes["dcregistry"] = time.Since(stepStart)
		}

		if rc.RuntimeOptions.IsMethodEnabled("ldapservices") {
			stepStart = time.Now()
			stepCtx, cancel := context.WithTimeout(context.Background(), rc.RemoteMethodTimeout)
			result.LdapServices = rc.collectLdapServices(stepCtx, target.IPAddress)
			cancel()
			methodTimes["ldapservices"] = time.Since(stepStart)
		}
	}

	totalTime := time.Since(totalStart)
	if len(methodTimes) > 0 {
		rc.logger.Log2("💻 [%s[] Collected in %s: %s", target.DNSHostName, totalTime.Round(time.Millisecond), formatMethodTimes(methodTimes))
	}

	return result
}
