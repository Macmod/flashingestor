package bloodhound

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/Macmod/flashingestor/bloodhound/builder"
)

// EnterpriseCARemoteCollectionResult holds data collected remotely from a CA.
type EnterpriseCARemoteCollectionResult struct {
	GUID                    string
	DN                      string
	CARegistryData          builder.CARegistryData
	HttpEnrollmentEndpoints []builder.CAEnrollmentEndpointAPIResult
	HostingComputer         string
}

// EnterpriseCACollectionTarget identifies a CA for remote data collection.
type EnterpriseCACollectionTarget struct {
	GUID        string
	DN          string
	DNSHostName string
	CAName      string
	Domain      string
}

func (rc *RemoteCollector) collectEnterpriseCARegistryData(ctx context.Context, caName string, objectSid string, targetDomain string, rpcMgr *RPCManager) builder.CARegistryData {
	msrpcObj, err := rpcMgr.GetOrCreateWinregRPC(ctx)
	if err != nil {
		errStr := err.Error()
		return builder.CARegistryData{
			CASecurity:                  builder.AceRegistryAPIResult{APIResult: builder.APIResult{FailureReason: &errStr}},
			EnrollmentAgentRestrictions: builder.EnrollmentAgentRegistryAPIResult{APIResult: builder.APIResult{FailureReason: &errStr}},
			IsUserSpecifiesSanEnabled:   builder.BoolRegistryAPIResult{APIResult: builder.APIResult{FailureReason: &errStr}},
			IsRoleSeparationEnabled:     builder.BoolRegistryAPIResult{APIResult: builder.APIResult{FailureReason: &errStr}},
		}
	}

	certAbuse := NewCertAbuseProcessor(targetDomain, msrpcObj, rc.auth, rpcMgr)
	targetHostname := rpcMgr.GetTargetHost()
	return builder.CARegistryData{
		CASecurity:                  certAbuse.ProcessRegistryEnrollmentPermissions(ctx, caName, targetHostname, objectSid, targetDomain),
		EnrollmentAgentRestrictions: certAbuse.ProcessEAPermissions(ctx, caName, targetHostname, objectSid, targetDomain),
		IsUserSpecifiesSanEnabled:   certAbuse.IsUserSpecifiesSanEnabled(caName),
		IsRoleSeparationEnabled:     certAbuse.IsRoleSeparationEnabled(caName),
	}
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
// Returns the result and a boolean indicating if the collection completed successfully (true = success, false = aborted).
// On timeout, returns partial results collected before the timeout.
func (rc *RemoteCollector) CollectRemoteEnterpriseCAWithContext(ctx context.Context, target EnterpriseCACollectionTarget) (EnterpriseCARemoteCollectionResult, bool) {
	result := EnterpriseCARemoteCollectionResult{GUID: target.GUID, DN: target.DN}
	done := make(chan struct{})
	var mu sync.Mutex

	go func() {
		rc.CollectRemoteEnterpriseCA(ctx, target, &result, &mu)
		close(done)
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

func (rc *RemoteCollector) CollectRemoteEnterpriseCA(ctx context.Context, target EnterpriseCACollectionTarget, result *EnterpriseCARemoteCollectionResult, mu *sync.Mutex) {
	totalStart := time.Now()
	rpcManager := NewRPCManager(target.DNSHostName, rc.auth)
	defer rpcManager.Close()

	if rc.noCrossDomain && !strings.EqualFold(target.Domain, rc.auth.Creds().Domain) {
		rc.logger.Log1("🦘 [yellow][%s[] Skipped Enterprise CA (cross-domain auth disabled)[-]", target.DNSHostName)
		return
	}

	methodTimes := rpcManager.GetMethodTimes()
	var stepStart time.Time

	resolveCtx, resolveCancel := context.WithTimeout(ctx, rc.RemoteMethodTimeout)
	objectSid, ok := resolveHostname(resolveCtx, rpcManager, target.Domain)
	resolveCancel()
	if ok {
		mu.Lock()
		result.HostingComputer = objectSid
		mu.Unlock()
	}

	if rc.RuntimeOptions.IsMethodEnabled("certservices") {
		if ctx.Err() != nil {
			return
		}
		stepStart = time.Now()
		stepCtx, cancel := context.WithTimeout(ctx, rc.RemoteMethodTimeout)
		httpEndpoints := rc.collectHttpEnrollmentEndpoints(stepCtx, target.CAName, rpcManager.GetTargetHost())
		cancel()
		methodTimes["certservices"] = time.Since(stepStart)
		mu.Lock()
		result.HttpEnrollmentEndpoints = httpEndpoints
		mu.Unlock()
	}

	if rc.RuntimeOptions.IsMethodEnabled("caregistry") {
		if ctx.Err() != nil {
			return
		}
		stepStart = time.Now()
		stepCtx, cancel := context.WithTimeout(ctx, rc.RemoteMethodTimeout)
		caRegData := rc.collectEnterpriseCARegistryData(stepCtx, target.CAName, objectSid, target.Domain, rpcManager)
		cancel()
		methodTimes["caregistry"] = time.Since(stepStart)
		mu.Lock()
		result.CARegistryData = caRegData
		mu.Unlock()
	}

	// Log method times summary
	if len(methodTimes) > 0 {
		totalTime := time.Since(totalStart)
		rc.logger.Log2("📋 [%s[] Collected in %s: %s", target.DNSHostName, totalTime.Round(time.Millisecond), formatMethodTimes(methodTimes))
	}
}
