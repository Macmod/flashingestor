package bloodhound

import (
	"context"

	"github.com/Macmod/flashingestor/bloodhound/builder"
)

// CollectionTarget identifies a computer for remote data collection.
type CollectionTarget struct {
	SID         string
	DNSHostName string
	SamName     string
	IPAddress   string
	IsDC        bool
	Domain      string
}

// RemoteCollectionResult holds all data collected remotely from a computer.
type RemoteCollectionResult struct {
	LocalGroups        []builder.LocalGroupAPIResult       `json:"LocalGroups"`
	Sessions           builder.SessionAPIResult            `json:"Sessions"`
	PrivilegedSessions builder.SessionAPIResult            `json:"PrivilegedSessions"`
	RegistrySessions   builder.SessionAPIResult            `json:"RegistrySessions"`
	DCRegistryData     builder.DCRegistryData              `json:"DCRegistryData"`
	NTLMRegistryData   builder.NTLMRegistryData            `json:"NTLMRegistryData"`
	UserRights         []builder.UserRightsAPIResult       `json:"UserRights"`
	IsWebClientRunning builder.IsWebClientRunningAPIResult `json:"IsWebClientRunning"`
	LdapServices       builder.LdapServicesResult          `json:"LdapServices"`
}

func (rcr *RemoteCollectionResult) StoreInComputer(computer *builder.Computer) {
	computer.LocalGroups = rcr.LocalGroups
	computer.PrivilegedSessions = rcr.PrivilegedSessions
	computer.Sessions = rcr.Sessions
	computer.RegistrySessions = rcr.RegistrySessions
	computer.DCRegistryData = rcr.DCRegistryData
	computer.NTLMRegistryData = rcr.NTLMRegistryData
	computer.UserRights = rcr.UserRights
	computer.IsWebClientRunning = rcr.IsWebClientRunning

	// Store LDAP services in Properties
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

func (rc *RemoteCollector) CollectRemoteComputer(ctx context.Context, target CollectionTarget) RemoteCollectionResult {
	result := RemoteCollectionResult{}

	//var stepStart time.Time

	if rc.RuntimeOptions.IsMethodEnabled("localgroups") {
		//fmt.Fprintf(os.Stderr, "🛠️  [blue]Collecting local group data from %s (%s)[-]\n", target.DNSHostName, target.IPAddress)
		//stepStart = time.Now()
		result.LocalGroups = rc.collectLocalGroups(ctx, target.IPAddress, target.DNSHostName, target.SID, target.IsDC, target.Domain)
		//fmt.Fprintf(os.Stderr, "   ⏱️  localgroups took %s\n", time.Since(stepStart).Round(time.Millisecond))
	}
	if rc.RuntimeOptions.IsMethodEnabled("loggedon") {
		//fmt.Fprintf(os.Stderr, "🛠️  [blue]Collecting privileged session data from %s (%s)[-]\n", target.DNSHostName, target.IPAddress)
		//stepStart = time.Now()
		result.PrivilegedSessions = rc.collectPrivilegedSessions(ctx, target.IPAddress, target.SamName, target.SID)
		//fmt.Fprintf(os.Stderr, "   ⏱️  loggedon took %s\n", time.Since(stepStart).Round(time.Millisecond))
	}
	if rc.RuntimeOptions.IsMethodEnabled("sessions") {
		//fmt.Fprintf(os.Stderr, "🛠️  [blue]Collecting session data from %s (%s)[-]\n", target.DNSHostName, target.IPAddress)
		//stepStart = time.Now()
		result.Sessions = rc.collectSessions(ctx, target.IPAddress, target.SID, target.Domain)
		//fmt.Fprintf(os.Stderr, "   ⏱️  sessions took %s\n", time.Since(stepStart).Round(time.Millisecond))
	}
	if rc.RuntimeOptions.IsMethodEnabled("regsessions") {
		//fmt.Fprintf(os.Stderr, "🛠️  [blue]Collecting regsession data from %s (%s)[-]\n", target.DNSHostName, target.IPAddress)
		//stepStart = time.Now()
		result.RegistrySessions = rc.collectRegistrySessions(ctx, target.IPAddress, target.SID)
		//fmt.Fprintf(os.Stderr, "   ⏱️  regsessions took %s\n", time.Since(stepStart).Round(time.Millisecond))
	}
	if rc.RuntimeOptions.IsMethodEnabled("ntlmregistry") {
		//fmt.Fprintf(os.Stderr, "🛠️  [blue]Collecting ntlm registry data from %s (%s)[-]\n", target.DNSHostName, target.IPAddress)
		//stepStart = time.Now()
		result.NTLMRegistryData = rc.collectNTLMRegistryData(ctx, target.IPAddress)
		//fmt.Fprintf(os.Stderr, "   ⏱️  ntlmregistry took %s\n", time.Since(stepStart).Round(time.Millisecond))
	}
	if rc.RuntimeOptions.IsMethodEnabled("userrights") {
		//fmt.Fprintf(os.Stderr, "🛠️  [blue]Collecting user rights data from %s (%s)[-]\n", target.DNSHostName, target.IPAddress)
		//stepStart = time.Now()
		result.UserRights = rc.collectUserRights(ctx, target.IPAddress, target.DNSHostName, target.SID, target.IsDC, target.Domain)
		//fmt.Fprintf(os.Stderr, "   ⏱️  userrights took %s\n", time.Since(stepStart).Round(time.Millisecond))
	}
	if rc.RuntimeOptions.IsMethodEnabled("webclient") {
		//fmt.Fprintf(os.Stderr, "🛠️  [blue]Collecting web client data from %s (%s)[-]\n", target.DNSHostName, target.IPAddress)
		//stepStart = time.Now()
		result.IsWebClientRunning = rc.collectIsWebClientRunning(ctx, target.IPAddress)
		//fmt.Fprintf(os.Stderr, "   ⏱️  webclient took %s\n", time.Since(stepStart).Round(time.Millisecond))
	}

	if target.IsDC {
		if rc.RuntimeOptions.IsMethodEnabled("dcregistry") {
			//fmt.Fprintf(os.Stderr, "🛠️  [blue]Collecting dcregistry data from %s (%s)[-]\n", target.DNSHostName, target.IPAddress)
			//stepStart = time.Now()
			result.DCRegistryData = rc.collectDCRegistryData(ctx, target.IPAddress)
			//fmt.Fprintf(os.Stderr, "   ⏱️  dcregistry took %s\n", time.Since(stepStart).Round(time.Millisecond))
		}

		if rc.RuntimeOptions.IsMethodEnabled("ldapservices") {
			//fmt.Fprintf(os.Stderr, "🛠️  [blue]Collecting LDAP services from %s (%s)[-]\n", target.DNSHostName, target.IPAddress)
			//stepStart = time.Now()
			result.LdapServices = rc.collectLdapServices(ctx, target.IPAddress)
			//fmt.Fprintf(os.Stderr, "   ⏱️  ldapservices took %s\n", time.Since(stepStart).Round(time.Millisecond))
		}
	}

	return result
}
