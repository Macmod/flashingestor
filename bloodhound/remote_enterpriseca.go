package bloodhound

import (
	"context"
	"fmt"
	"os"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/msrpc"
)

// EnterpriseCARemoteCollectionResult holds data collected remotely from a CA.
type EnterpriseCARemoteCollectionResult struct {
	CARegistryData          builder.CARegistryData                  `json:"CARegistryData"`
	HttpEnrollmentEndpoints []builder.CAEnrollmentEndpointAPIResult `json:"HttpEnrollmentEndpoints"`
	HostingComputer         string                                  `json:"HostingComputer"`
}

// EnterpriseCACollectionTarget identifies a CA for remote data collection.
type EnterpriseCACollectionTarget struct {
	GUID        string
	DNSHostName string
	CAName      string
	Domain      string
	IPAddress   string
}

func (rc *RemoteCollector) collectEnterpriseCARegistryData(ctx context.Context, caName string, targetHostname string, objectSid string, targetDomain string) builder.CARegistryData {
	result := builder.CARegistryData{}

	msrpcObj, err := msrpc.NewMSRPC(ctx, targetHostname, rc.auth)
	if err != nil {
		return result
	}
	defer msrpcObj.Close()

	certAbuse := NewCertAbuseProcessor(targetDomain, &msrpcObj, rc.auth)
	if certAbuse == nil {
		return result
	}

	fmt.Fprintf(os.Stderr, "RegEnrollPerms\n")
	result.CASecurity = certAbuse.ProcessRegistryEnrollmentPermissions(ctx, caName, targetHostname, objectSid, targetDomain)
	fmt.Fprintf(os.Stderr, "ProcessEAPerms\n")
	result.EnrollmentAgentRestrictions = certAbuse.ProcessEAPermissions(ctx, caName, targetHostname, objectSid, targetDomain)
	fmt.Fprintf(os.Stderr, "IsUserSpecifiesSanEnabled\n")
	result.IsUserSpecifiesSanEnabled = certAbuse.IsUserSpecifiesSanEnabled(caName)
	fmt.Fprintf(os.Stderr, "IsRoleSeparationEnabled\n")
	result.IsRoleSeparationEnabled = certAbuse.IsRoleSeparationEnabled(caName)

	return result
}

func (rc *RemoteCollector) collectHttpEnrollmentEndpoints(ctx context.Context, caName string, targetHost string) []builder.CAEnrollmentEndpointAPIResult {
	caEnrollment := NewCAEnrollmentProcessor(targetHost, caName, rc.auth, nil)
	caEndpoints, err := caEnrollment.ScanCAEnrollmentEndpoints(ctx)
	if err != nil {
		return nil
	}

	return caEndpoints
}

func (rc *RemoteCollector) CollectRemoteEnterpriseCA(ctx context.Context, target EnterpriseCACollectionTarget) EnterpriseCARemoteCollectionResult {
	result := EnterpriseCARemoteCollectionResult{}

	objectSid, ok := builder.ResolveHostToSid(target.DNSHostName, target.Domain)
	if ok {
		result.HostingComputer = objectSid
	}

	// Use IPAddress for RPC connections if available, otherwise fall back to DNSHostName
	targetHost := target.IPAddress
	if targetHost == "" {
		targetHost = target.DNSHostName
	}

	if rc.RuntimeOptions.IsMethodEnabled("caregistry") {
		fmt.Fprintf(os.Stderr, "[blue]🛠️  Collecting Enterprise CA registry data from %s (%s)[-]\n", target.DNSHostName, target.IPAddress)
		result.CARegistryData = rc.collectEnterpriseCARegistryData(ctx, target.CAName, targetHost, objectSid, target.Domain)
		fmt.Fprintf(os.Stderr, "[blue]🛠️  Collecting HTTPEnrollmentEndpoints CA registry data from %s (%s)[-]\n", target.DNSHostName, target.IPAddress)
		result.HttpEnrollmentEndpoints = rc.collectHttpEnrollmentEndpoints(ctx, target.CAName, targetHost)
	}
	return result
}

func MergeRemoteEnterpriseCACollection(enterpriseCa *builder.EnterpriseCA, rc *EnterpriseCARemoteCollectionResult) {
	enterpriseCa.CARegistryData = rc.CARegistryData
	enterpriseCa.HttpEnrollmentEndpoints = rc.HttpEnrollmentEndpoints
	enterpriseCa.HostingComputer = rc.HostingComputer
	enterpriseCa.Properties.EnrollmentAgentRestrictionsCollected = rc.CARegistryData.EnrollmentAgentRestrictions.Collected
	enterpriseCa.Properties.IsUserSpecifiesSanEnabledCollected = rc.CARegistryData.IsUserSpecifiesSanEnabled.Collected
	enterpriseCa.Properties.RoleSeparationEnabledCollected = rc.CARegistryData.IsRoleSeparationEnabled.Collected
	enterpriseCa.Properties.CASecurityCollected = rc.CARegistryData.CASecurity.Collected
}
