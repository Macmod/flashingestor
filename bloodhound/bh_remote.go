package bloodhound

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/config"
	"github.com/Macmod/flashingestor/core"
	gildap "github.com/Macmod/flashingestor/ldap"
	"github.com/Macmod/flashingestor/reader"
	"github.com/go-ldap/ldap/v3"
	"github.com/vmihailenco/msgpack"
)

// RemoteCollector executes remote data collection from AD computers and CAs.
type RemoteCollector struct {
	auth           *config.CredentialMgr
	RuntimeOptions *config.RuntimeOptions
}

// NewRemoteCollector creates a collector with the given credentials and options.
func NewRemoteCollector(authenticator *config.CredentialMgr, runtimeOptions *config.RuntimeOptions) *RemoteCollector {
	return &RemoteCollector{
		auth:           authenticator,
		RuntimeOptions: runtimeOptions,
	}
}

type RemoteCollectionUpdate = core.RemoteCollectionUpdate

const TotalRemoteSteps = 4

// PerformRemoteCollection gathers data from computers and CAs using RPC and HTTP.
func (bh *BH) PerformRemoteCollection(auth *config.CredentialMgr) {
	// Initialize builder state
	forestMapPath := filepath.Join(bh.LdapFolder, "ForestDomains.json")
	builder.BState().Init(forestMapPath)

	// Create remote collector with authentication options
	collector := NewRemoteCollector(auth, bh.RuntimeOptions)

	notifyAbort := func(currentStep int) bool {
		if bh.IsAborted() {
			// Mark remaining steps as skipped
			for step := currentStep + 1; step <= TotalRemoteSteps; step++ {
				if bh.RemoteCollectionUpdates != nil {
					bh.RemoteCollectionUpdates <- RemoteCollectionUpdate{
						Step:   step,
						Status: "skipped",
					}
				}
			}
			return true
		}
		return false
	}

	bh.runRemoteStep(1, func() { bh.loadRemoteCollectionCache(1) })
	if notifyAbort(1) {
		return
	}

	// Collect from Enterprise CAs
	enterpriseCAs := bh.loadEnterpriseCATargets()
	if notifyAbort(1) {
		return
	}

	bh.runRemoteStep(2, func() { bh.collectEnterpriseCAData(2, enterpriseCAs, collector) })
	if notifyAbort(2) {
		return
	}

	// Collect from computers
	var computers []CollectionTarget
	bh.runRemoteStep(3, func() { computers = bh.loadComputerTargets(3) })
	if notifyAbort(3) {
		return
	}

	bh.Log <- fmt.Sprintf("🎯 About to perform active collection for %d computers", len(computers))
	bh.runRemoteStep(4, func() { bh.collectComputerData(4, computers, collector) })
}

// runRemoteStep runs a remote collection step and sends progress events
func (bh *BH) runRemoteStep(row int, stepFunc func()) {
	if bh.IsAborted() {
		return
	}

	if bh.RemoteCollectionUpdates != nil {
		bh.RemoteCollectionUpdates <- RemoteCollectionUpdate{
			Step:   row,
			Status: "running",
		}
	}

	startTime := time.Now()
	stepFunc()
	elapsed := time.Since(startTime)

	if bh.IsAborted() {
		if bh.RemoteCollectionUpdates != nil {
			bh.RemoteCollectionUpdates <- RemoteCollectionUpdate{
				Step:    row,
				Status:  "aborted",
				Elapsed: elapsed.Round(10 * time.Millisecond).String(),
			}
		}
		return
	}

	if bh.RemoteCollectionUpdates != nil {
		bh.RemoteCollectionUpdates <- RemoteCollectionUpdate{
			Step:    row,
			Status:  "done",
			Elapsed: elapsed.Round(10 * time.Millisecond).String(),
		}
	}
}

// loadRemoteCollectionCache loads necessary caches for remote collection
func (bh *BH) loadRemoteCollectionCache(step int) {
	startTime := time.Now()
	lastUpdateTime := startTime
	var lastCount int
	totalProcessed := 0
	totalEntries := 0

	neededCaches := []string{"domains", "trusts", "users", "groups", "computers", "configuration"}

	// First pass: open all readers and read their lengths
	type readerInfo struct {
		reader     *reader.MPReader
		fileName   string
		identifier string
	}
	readers := make([]readerInfo, 0)

	for _, cacheKey := range neededCaches {
		filePaths, _ := bh.GetPaths(cacheKey)
		for _, filePath := range filePaths {
			// Check if this cache has already been loaded
			if builder.BState().IsCacheLoaded(filePath) {
				bh.Log <- fmt.Sprintf("🦘 Skipped %s (already loaded)", filePath)
				continue
			}

			r, err := reader.NewMPReader(filePath)
			if err != nil {
				bh.Log <- fmt.Sprintf("❌ Error opening file %s: %v", filePath, err)
				continue
			}

			numEntries, err := r.ReadLength()
			if err != nil {
				bh.Log <- fmt.Sprintf("❌ Error reading length of %s: %v", filePath, err)
				r.Close()
				continue
			}

			totalEntries += numEntries
			readers = append(readers, readerInfo{
				reader:     r,
				fileName:   filePath,
				identifier: cacheKey,
			})
		}
	}

	// Ensure all readers are closed when done
	defer func() {
		for _, info := range readers {
			info.reader.Close()
		}
	}()

	progressCallback := func(_ int, _ int) {
		totalProcessed++

		// Throttle updates to avoid flooding the channel
		now := time.Now()
		if now.Sub(lastUpdateTime) < 100*time.Millisecond && totalProcessed < totalEntries {
			return
		}

		elapsed := time.Since(startTime)
		var percent float64
		if totalEntries > 0 {
			percent = float64(totalProcessed) / float64(totalEntries) * 100.0
		}

		// Calculate metrics
		metrics := calculateProgressMetrics(totalProcessed, totalEntries, startTime, &lastUpdateTime, &lastCount)

		if bh.RemoteCollectionUpdates != nil {
			bh.RemoteCollectionUpdates <- RemoteCollectionUpdate{
				Step:      step,
				Processed: totalProcessed,
				Total:     totalEntries,
				Percent:   percent,
				Speed:     metrics.speedText,
				AvgSpeed:  metrics.avgSpeedText,
				ETA:       metrics.etaText,
				Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
			}
		}
	}

	// Second pass: process all readers sequentially
	for _, info := range readers {
		if bh.IsAborted() {
			break
		}

		filePath := info.reader.GetPath()
		bh.Log <- fmt.Sprintf("📦 Loading %s", filePath)

		builder.BState().CacheEntries(info.reader, info.identifier, bh.Log, bh.IsAborted, progressCallback)

		// Mark this cache as loaded
		builder.BState().MarkCacheLoaded(filePath)

		bh.Log <- fmt.Sprintf("✅ %s loaded", filePath)
	}
}

// loadEnterpriseCATargets extracts enterprise CA targets from configuration
func (bh *BH) loadEnterpriseCATargets() []EnterpriseCACollectionTarget {
	var targets []EnterpriseCACollectionTarget
	configPaths, err := bh.GetPaths("configuration")
	if err != nil {
		return targets
	}

	for _, configPath := range configPaths {
		mpReader, err := reader.NewMPReader(configPath)
		if err != nil {
			bh.Log <- fmt.Sprintf("❌ Error opening configuration file: %v", err)
			continue
		}
		defer mpReader.Close()

		_, err = mpReader.ReadLength()
		if err != nil {
			bh.Log <- fmt.Sprintf("❌ Error reading length of configuration file: %v", err)
			continue
		}

		originalEntry := new(ldap.Entry)
		var entry gildap.LDAPEntry

		for i := 0; i < mpReader.Length(); i++ {
			if bh.IsAborted() {
				break
			}

			*originalEntry = ldap.Entry{}
			if err := mpReader.ReadEntry(originalEntry); err != nil {
				bh.Log <- fmt.Sprintf("❌ Error decoding configuration entry: %v", err)
				continue
			}

			entry.Init(originalEntry)

			objectClasses := entry.GetAttrVals("objectClass", []string{})
			if slices.Contains(objectClasses, "pKIEnrollmentService") {
				caName := entry.GetAttrVal("name", "")
				dNSHostName := entry.GetAttrVal("dNSHostName", "")
				domain := entry.GetDomainFromDN()

				if caName != "" && dNSHostName != "" && domain != "" {
					targets = append(targets, EnterpriseCACollectionTarget{
						GUID:        entry.GetGUID(),
						DNSHostName: dNSHostName,
						CAName:      caName,
						Domain:      domain,
					})
				}
			}
		}
	}

	/*
		if len(targets) > 0 {
			firstTarget := targets[0]
			for i := 0; i < 20; i++ {
				targets = append(targets, firstTarget)
			}
		}
	*/

	return targets
}

// collectEnterpriseCAData collects data from enterprise CAs
func (bh *BH) collectEnterpriseCAData(step int, targets []EnterpriseCACollectionTarget, collector *RemoteCollector) {
	bh.Log <- fmt.Sprintf("🎯 About to perform active collection for %d enterprise CAs", len(targets))

	startTime := time.Now()
	lastUpdateTime := startTime
	lastCount := 0
	successCount := 0
	caResults := make(map[string]EnterpriseCARemoteCollectionResult)

	for idx, caTarget := range targets {
		if bh.IsAborted() {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), bh.RemoteTimeout)

		// Collect CA data
		// If DNSHostName is not an IP, resolve it using the custom resolver
		// to get the IP and store it in IPAddress field
		ip := net.ParseIP(caTarget.DNSHostName)
		if ip != nil {
			// DNSHostName is already an IP address
			caTarget.IPAddress = caTarget.DNSHostName
		} else {
			// Resolve DNSHostName to IP address
			addrs, err := bh.Resolver.LookupHost(ctx, caTarget.DNSHostName)
			if err == nil && len(addrs) > 0 {
				caTarget.IPAddress = addrs[0]
			}
		}

		if caTarget.IPAddress != "" {
			res := collector.CollectRemoteEnterpriseCA(ctx, caTarget)

			// Store results by GUID
			caResults[caTarget.GUID] = res
			successCount++
		}

		cancel()

		// Update progress in real-time
		processedCount := idx + 1
		elapsed := time.Since(startTime)

		var percent float64
		if len(targets) > 0 {
			percent = float64(processedCount) / float64(len(targets)) * 100.0
		}

		// Calculate metrics
		metrics := calculateProgressMetrics(processedCount, len(targets), startTime, &lastUpdateTime, &lastCount)

		// Calculate success
		var successPercent float64
		if len(targets) > 0 {
			successPercent = float64(successCount) / float64(len(targets)) * 100.0
		}
		successText := fmt.Sprintf("%d/%d (%.1f%%)", successCount, len(targets), successPercent)

		if bh.RemoteCollectionUpdates != nil {
			bh.RemoteCollectionUpdates <- RemoteCollectionUpdate{
				Step:      step,
				Processed: processedCount,
				Total:     len(targets),
				Percent:   percent,
				Speed:     metrics.speedText,
				AvgSpeed:  metrics.avgSpeedText,
				Success:   successText,
				ETA:       metrics.etaText,
				Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
			}
		}
	}

	// Update final status
	// Store results - convert to pointer map
	if bh.RemoteEnterpriseCACollection == nil {
		bh.RemoteEnterpriseCACollection = make(map[string]*EnterpriseCARemoteCollectionResult)
	}
	for guid, result := range caResults {
		resultCopy := result
		bh.RemoteEnterpriseCACollection[guid] = &resultCopy
	}

	// Write CA results to file
	if len(caResults) > 0 {
		remoteCAFile := filepath.Join(bh.ActiveFolder, "RemoteEnterpriseCA.msgpack")
		outFile, err := os.Create(remoteCAFile)
		if err != nil {
			bh.Log <- fmt.Sprintf("❌ Failed to create CA results file: %v", err)
			return
		}
		defer outFile.Close()

		encoder := msgpack.NewEncoder(outFile)
		if err := encoder.Encode(caResults); err != nil {
			bh.Log <- fmt.Sprintf("❌ Failed to write CA results: %v", err)
		} else {
			if fileInfo, err := os.Stat(remoteCAFile); err == nil {
				bh.Log <- fmt.Sprintf("✅ CA results saved to: %s (%s)", remoteCAFile, formatFileSize(fileInfo.Size()))
			} else {
				bh.Log <- fmt.Sprintf("🫠 [yellow]Problem saving %s: %v[-]", remoteCAFile, err)
			}
		}
	}
}

// loadComputerTargets performs DNS lookups and returns viable computer targets
func (bh *BH) loadComputerTargets(step int) []CollectionTarget {
	var targets []CollectionTarget
	computerPaths, err := bh.GetPaths("computers")
	if err != nil {
		return targets
	}

	totalComputers := 0

	readers := make([]*reader.MPReader, 0, len(computerPaths))
	for _, computerPath := range computerPaths {
		mpReader, err := reader.NewMPReader(computerPath)
		if err != nil {
			bh.Log <- fmt.Sprintf("❌ Error opening computers file: %v", err)
			continue
		}
		defer mpReader.Close()

		length, err := mpReader.ReadLength()
		if err != nil {
			bh.Log <- fmt.Sprintf("❌ Error reading length of computers file: %v", err)
			continue
		}

		readers = append(readers, mpReader)

		totalComputers += length
	}

	startTime := time.Now()
	lastUpdateTime := startTime
	entryCount := atomic.Int32{}
	successCount := atomic.Int32{}

	// Job structure for DNS lookup tasks
	type dnsJob struct {
		computerSid    string
		dNSHostName    string
		sAMAccountName string
		isDC           bool
		domain         string
	}

	// Create channels for job distribution
	jobs := make(chan dnsJob, bh.DNSWorkers*2)
	results := make(chan CollectionTarget, bh.DNSWorkers*2)

	// Start DNS worker pool
	var wg sync.WaitGroup
	for w := 0; w < bh.DNSWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if bh.IsAborted() {
					continue
				}

				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
				addrs, err := bh.Resolver.LookupHost(ctx, job.dNSHostName)
				cancel()

				if err == nil && len(addrs) > 0 {
					successCount.Add(1)
					results <- CollectionTarget{
						SID:         job.computerSid,
						DNSHostName: job.dNSHostName,
						SamName:     job.sAMAccountName,
						IPAddress:   addrs[0],
						IsDC:        job.isDC,
						Domain:      job.domain,
					}
				} else {
					bh.Log <- fmt.Sprintf("🫠 [yellow]Could not resolve %s: %v[-]", job.dNSHostName, err)
				}
			}
		}()
	}

	// Start result collector goroutine
	done := make(chan struct{})
	var targetsMu sync.Mutex
	go func() {
		for result := range results {
			targetsMu.Lock()
			targets = append(targets, result)
			targetsMu.Unlock()
		}
		close(done)
	}()

	// Start progress updater goroutine
	progressDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		lastCountLocal := 0

		for {
			select {
			case <-progressDone:
				return
			case <-ticker.C:
				currentCount := int(entryCount.Load())
				elapsed := time.Since(startTime)

				var percent float64
				if totalComputers > 0 {
					percent = float64(currentCount) / float64(totalComputers) * 100.0
				}

				// Calculate metrics using helper
				metrics := calculateProgressMetrics(currentCount, totalComputers, startTime, &lastUpdateTime, &lastCountLocal)

				// Calculate success
				currentSuccess := int(successCount.Load())
				var successText string
				if currentCount > 0 {
					successPercent := float64(currentSuccess) / float64(currentCount) * 100.0
					successText = fmt.Sprintf("%d/%d (%.1f%%)", currentSuccess, currentCount, successPercent)
				} else {
					successText = "0/0"
				}

				if bh.RemoteCollectionUpdates != nil {
					bh.RemoteCollectionUpdates <- RemoteCollectionUpdate{
						Step:      step,
						Processed: currentCount,
						Total:     totalComputers,
						Percent:   percent,
						Speed:     metrics.speedText,
						AvgSpeed:  metrics.avgSpeedText,
						Success:   successText,
						ETA:       metrics.etaText,
						Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
					}
				}
			}
		}
	}()

	// Read entries and submit DNS lookup jobs
	for _, reader := range readers {
		originalEntry := new(ldap.Entry)
		var entry gildap.LDAPEntry

		for i := 0; i < reader.Length(); i++ {
			if bh.IsAborted() {
				break
			}

			*originalEntry = ldap.Entry{}
			if err := reader.ReadEntry(originalEntry); err != nil {
				bh.Log <- fmt.Sprintf("❌ Error decoding computer: %v", err)
				continue
			}

			entry.Init(originalEntry)
			entryCount.Add(1)

			dNSHostName := entry.GetAttrVal("dNSHostName", "")
			sAMAccountName := entry.GetAttrVal("sAMAccountName", "")

			if dNSHostName != "" && sAMAccountName != "" {
				jobs <- dnsJob{
					computerSid:    entry.GetSID(),
					dNSHostName:    dNSHostName,
					sAMAccountName: sAMAccountName,
					isDC:           entry.IsDC(),
					domain:         entry.GetDomainFromDN(),
				}
			}
		}

		if bh.IsAborted() {
			break
		}
	}

	// Close jobs channel and wait for workers to finish
	close(jobs)
	wg.Wait()
	close(results)
	<-done

	// Stop progress updater
	close(progressDone)

	if bh.IsAborted() {
		return targets
	}

	return targets
}

// collectComputerData collects data from computers using worker pool
func (bh *BH) collectComputerData(step int, computers []CollectionTarget, collector *RemoteCollector) {
	numWorkers := bh.RemoteWorkers
	timeout := bh.RemoteTimeout

	// Create output file
	remoteResultsFile := filepath.Join(bh.ActiveFolder, "RemoteComputers.msgpack")
	outFile, err := os.Create(remoteResultsFile)
	if err != nil {
		bh.Log <- fmt.Sprintf("❌ Failed to create results file: %v", err)
		return
	}
	defer outFile.Close()

	encoder := msgpack.NewEncoder(outFile)
	var encoderMu sync.Mutex

	// Setup worker pool
	type collectionTask struct {
		target CollectionTarget
	}

	targetChan := make(chan collectionTask, numWorkers*2)
	resultChan := make(chan struct {
		sid    string
		result RemoteCollectionResult
	}, numWorkers*2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for task := range targetChan {
				if bh.IsAborted() {
					return
				}

				collectionCtx, collectionCancel := context.WithTimeout(ctx, timeout)
				result := collector.CollectRemoteComputer(collectionCtx, task.target)
				collectionCancel()

				select {
				case resultChan <- struct {
					sid    string
					result RemoteCollectionResult
				}{sid: task.target.SID, result: result}:
				case <-ctx.Done():
					return
				}
			}
		}(i)
	}

	// Process results
	workersDone := make(chan struct{})
	var processedCount int
	var successCount int
	var finalAvgRate float64
	var finalElapsed time.Duration

	go bh.processComputerResults(step, resultChan, workersDone, encoder, &encoderMu, computers, &processedCount, &successCount, &finalAvgRate, &finalElapsed)

	// Feed targets to workers
	go func() {
		for _, target := range computers {
			if bh.IsAborted() {
				break
			}
			select {
			case targetChan <- collectionTask{target: target}:
			case <-ctx.Done():
				return
			}
		}
		close(targetChan)
	}()

	// Wait for all workers, then close result channel
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Wait for result processor
	<-workersDone

	// Check if aborted before finalizing
	if bh.IsAborted() {
		if fileInfo, err := os.Stat(remoteResultsFile); err == nil {
			bh.Log <- fmt.Sprintf("✅ Computer results saved to: %s (%s)", remoteResultsFile, formatFileSize(fileInfo.Size()))
		} else {
			bh.Log <- fmt.Sprintf("🫠 [yellow]Problem saving %s: %v[-]", remoteResultsFile, err)
		}
		return
	}

	// Update final status
	bh.finalizeComputerCollection(step, len(computers), successCount, finalElapsed)
	if fileInfo, err := os.Stat(remoteResultsFile); err == nil {
		bh.Log <- fmt.Sprintf("✅ Computer results saved to: %s (%s)", remoteResultsFile, formatFileSize(fileInfo.Size()))
	} else {
		bh.Log <- fmt.Sprintf("🫠 [yellow]Problem saving %s: %v[-]", remoteResultsFile, err)
	}
}

func (bh *BH) checkAnyRpcSuccess(result RemoteCollectionResult) bool {
	// Kind of a hacky way to check if "any relevant call succeeded"
	// but for now it works :)
	if result.Sessions.Collected == true ||
		result.PrivilegedSessions.Collected == true ||
		result.RegistrySessions.Collected == true ||
		result.NTLMRegistryData.Collected == true ||
		result.IsWebClientRunning.Collected == true ||
		result.DCRegistryData.CertificateMappingMethods != nil ||
		result.DCRegistryData.StrongCertificateBindingEnforcement != nil ||
		result.DCRegistryData.VulnerableNetlogonSecurityDescriptor != nil {
		return true
	}

	if result.UserRights != nil && len(result.UserRights) > 0 {
		if result.UserRights[0].Collected == true {
			return true
		}
	}

	if result.LocalGroups != nil && len(result.LocalGroups) > 0 {
		if result.LocalGroups[0].Collected == true {
			return true
		}
	}

	return false
}

// processComputerResults handles result processing from collection workers
func (bh *BH) processComputerResults(step int, resultChan chan struct {
	sid    string
	result RemoteCollectionResult
}, done chan struct{}, encoder *msgpack.Encoder, encoderMu *sync.Mutex,
	computers []CollectionTarget, processedCount, successCount *int,
	finalAvgRate *float64, finalElapsed *time.Duration) {

	defer close(done)
	startTime := time.Now()
	lastCheckTime := startTime
	lastProcessedCount := 0

	resultBuffer := make(map[string]RemoteCollectionResult, bh.RemoteWriteBuff)

	for res := range resultChan {
		*processedCount++

		// Buffer results
		resultBuffer[res.sid] = res.result

		// Flush buffer when full
		if len(resultBuffer) >= bh.RemoteWriteBuff {
			encoderMu.Lock()
			if err := encoder.Encode(resultBuffer); err != nil {
				bh.Log <- fmt.Sprintf("Failed to write results: %v", err)
			}
			encoderMu.Unlock()
			resultBuffer = make(map[string]RemoteCollectionResult, bh.RemoteWriteBuff)
		}

		// Count successes
		if bh.checkAnyRpcSuccess(res.result) {
			*successCount++
		}

		// Progress reporting
		if *processedCount%1 == 0 {
			now := time.Now()
			elapsed := now.Sub(startTime)
			avgRate := float64(*processedCount) / elapsed.Seconds()

			timeSinceLastCheck := now.Sub(lastCheckTime)
			processSinceLastCheck := *processedCount - lastProcessedCount
			instRate := float64(processSinceLastCheck) / timeSinceLastCheck.Seconds()

			lastCheckTime = now
			lastProcessedCount = *processedCount

			remaining := len(computers) - *processedCount
			var eta time.Duration
			if avgRate > 0 {
				eta = time.Duration(float64(remaining)/avgRate) * time.Second
			}

			progressPercent := float64(*processedCount) / float64(len(computers)) * 100.0
			successPercent := float64(*successCount) / float64(len(computers)) * 100.0

			// Send channel update
			if bh.RemoteCollectionUpdates != nil {
				bh.RemoteCollectionUpdates <- RemoteCollectionUpdate{
					Step:      step,
					Processed: *processedCount,
					Total:     len(computers),
					Percent:   progressPercent,
					Speed:     fmt.Sprintf("%.1f/s", instRate),
					AvgSpeed:  fmt.Sprintf("%.1f/s", avgRate),
					Success:   fmt.Sprintf("%d/%d (%.1f%%)", *successCount, len(computers), successPercent),
					ETA:       eta.Round(time.Second).String(),
					Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
				}
			}
		}
	}

	// Flush remaining buffer
	if len(resultBuffer) > 0 {
		encoderMu.Lock()
		if err := encoder.Encode(resultBuffer); err != nil {
			bh.Log <- fmt.Sprintf("Failed to write final results: %v", err)
		}
		encoderMu.Unlock()
	}

	// Calculate final stats
	totalElapsed := time.Since(startTime)
	*finalAvgRate = float64(len(computers)) / totalElapsed.Seconds()
	*finalElapsed = totalElapsed
}

// finalizeComputerCollection finalizes computer collection statistics
func (bh *BH) finalizeComputerCollection(step, total, success int, elapsed time.Duration) {
	// Final update sent via runRemoteStep
}
