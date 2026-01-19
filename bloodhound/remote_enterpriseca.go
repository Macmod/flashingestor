package bloodhound

import (
	"context"
	"time"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/msrpc"
)

// EnterpriseCARemoteCollectionResult holds data collected remotely from a CA.
type EnterpriseCARemoteCollectionResult struct {
	GUID                    string                                  `json:"GUID"`
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

	msrpcObj, err := msrpc.NewWinregRPC(ctx, targetHostname, rc.auth)
	if err != nil {
		return result
	}
	defer msrpcObj.Close()

	certAbuse := NewCertAbuseProcessor(targetDomain, msrpcObj, rc.auth)
	if certAbuse == nil {
		return result
	}

	result.CASecurity = certAbuse.ProcessRegistryEnrollmentPermissions(ctx, caName, targetHostname, objectSid, targetDomain)
	result.EnrollmentAgentRestrictions = certAbuse.ProcessEAPermissions(ctx, caName, targetHostname, objectSid, targetDomain)
	result.IsUserSpecifiesSanEnabled = certAbuse.IsUserSpecifiesSanEnabled(caName)
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

// CollectRemoteEnterpriseCAWithContext wraps CollectRemoteEnterpriseCA with hard timeout enforcement.
func (rc *RemoteCollector) CollectRemoteEnterpriseCAWithContext(ctx context.Context, target EnterpriseCACollectionTarget) EnterpriseCARemoteCollectionResult {
	resultCh := make(chan EnterpriseCARemoteCollectionResult, 1)

	go func() {
		resultCh <- rc.CollectRemoteEnterpriseCA(target)
	}()

	select {
	case result := <-resultCh:
		return result
	case <-ctx.Done():
		rc.logger.Log1("[yellow](%s) CA aborted: %v[-]", target.DNSHostName, ctx.Err())
		return EnterpriseCARemoteCollectionResult{}
	}
}

func (rc *RemoteCollector) CollectRemoteEnterpriseCA(target EnterpriseCACollectionTarget) EnterpriseCARemoteCollectionResult {
	totalStart := time.Now()

	methodTimes := make(map[string]time.Duration)
	result := EnterpriseCARemoteCollectionResult{
		GUID: target.GUID,
	}

	var stepStart time.Time

	resolveCtx, resolveCancel := context.WithTimeout(context.Background(), rc.RemoteMethodTimeout)
	objectSid, ok := resolveHostname(resolveCtx, rc.auth, target.DNSHostName, target.Domain)
	resolveCancel()
	if ok {
		result.HostingComputer = objectSid
	}

	// Use IPAddress for RPC connections if available, otherwise fall back to DNSHostName
	targetHost := target.IPAddress
	if targetHost == "" {
		targetHost = target.DNSHostName
	}

	if rc.RuntimeOptions.IsMethodEnabled("certservices") {
		stepStart = time.Now()
		stepCtx, cancel := context.WithTimeout(context.Background(), rc.RemoteMethodTimeout)
		result.HttpEnrollmentEndpoints = rc.collectHttpEnrollmentEndpoints(stepCtx, target.CAName, targetHost)
		cancel()
		methodTimes["certservices"] = time.Since(stepStart)
	}

	if rc.RuntimeOptions.IsMethodEnabled("caregistry") {
		stepStart = time.Now()
		stepCtx, cancel := context.WithTimeout(context.Background(), rc.RemoteMethodTimeout)
		result.CARegistryData = rc.collectEnterpriseCARegistryData(stepCtx, target.CAName, targetHost, objectSid, target.Domain)
		cancel()
		methodTimes["caregistry"] = time.Since(stepStart)
	}

	// Log method times summary
	if len(methodTimes) > 0 {
		totalTime := time.Since(totalStart)
		rc.logger.Log2("(%s) Total %s: %s", target.DNSHostName, totalTime.Round(time.Millisecond), formatMethodTimes(methodTimes))
	}

	return result
}

func mergeRemoteEnterpriseCACollection(enterpriseCa *builder.EnterpriseCA, rc *EnterpriseCARemoteCollectionResult) {
	enterpriseCa.CARegistryData = rc.CARegistryData
	enterpriseCa.HttpEnrollmentEndpoints = rc.HttpEnrollmentEndpoints
	enterpriseCa.HostingComputer = rc.HostingComputer
	enterpriseCa.Properties.EnrollmentAgentRestrictionsCollected = rc.CARegistryData.EnrollmentAgentRestrictions.Collected
	enterpriseCa.Properties.IsUserSpecifiesSanEnabledCollected = rc.CARegistryData.IsUserSpecifiesSanEnabled.Collected
	enterpriseCa.Properties.RoleSeparationEnabledCollected = rc.CARegistryData.IsRoleSeparationEnabled.Collected
	enterpriseCa.Properties.CASecurityCollected = rc.CARegistryData.CASecurity.Collected
}
