package bloodhound

import (
	"bufio"
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
	auth                *config.CredentialMgr
	RuntimeOptions      *config.RuntimeOptions
	RemoteMethodTimeout time.Duration
	logger              *core.Logger
}

// NewRemoteCollector creates a collector with the given credentials and options.
func NewRemoteCollector(authenticator *config.CredentialMgr, runtimeOptions *config.RuntimeOptions, methodTimeout time.Duration, logger *core.Logger) *RemoteCollector {
	return &RemoteCollector{
		auth:                authenticator,
		RuntimeOptions:      runtimeOptions,
		RemoteMethodTimeout: methodTimeout,
		logger:              logger,
	}
}

type RemoteCollectionUpdate = core.RemoteCollectionUpdate

const (
	TotalRemoteSteps = 6
)

// formatSuccessRate formats a success count/total as percentage string
func formatSuccessRate(success, total int) string {
	if total == 0 {
		return "0/0"
	}
	percent := float64(success) / float64(total) * 100.0
	return fmt.Sprintf("%d/%d (%.1f%%)", success, total, percent)
}

// PerformRemoteCollection gathers data from computers and CAs using RPC and HTTP.
func (bh *BH) PerformRemoteCollection(auth *config.CredentialMgr) {
	// Initialize builder state (clears old data)
	forestMapPath := filepath.Join(bh.LdapFolder, "ForestDomains.json")
	builder.BState().Init(forestMapPath)

	// Create remote collector with authentication options
	collector := NewRemoteCollector(auth, bh.RuntimeOptions, bh.RemoteMethodTimeout, bh.Logger)

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

	// Load computer targets from LDAP
	var allComputers []CollectionTarget
	bh.runRemoteStep(2, func() { allComputers = bh.loadComputerTargets(2) })
	if notifyAbort(2) {
		return
	}

	bh.log("✅ Found %d valid computers to collect data from", len(allComputers))

	// Run availability checks
	var availableComputers []CollectionTarget
	bh.runRemoteStep(3, func() { availableComputers = bh.checkComputerAvailability(3, allComputers, collector) })
	if notifyAbort(3) {
		return
	}

	// Perform DNS lookups on available computers
	var computers []CollectionTarget
	bh.runRemoteStep(4, func() { computers = bh.performDNSLookups(4, availableComputers) })
	if notifyAbort(4) {
		return
	}

	bh.log("✅ Successfully resolved %d/%d computers via DNS", len(computers), len(availableComputers))

	// Collect from Enterprise CAs
	enterpriseCAs := bh.loadEnterpriseCATargets()
	if notifyAbort(4) {
		return
	}

	bh.log("🎯 About to perform active collection for %d enterprise CAs", len(enterpriseCAs))
	bh.runRemoteStep(5, func() { bh.CollectRemoteEnterpriseCA(5, enterpriseCAs, collector) })
	if notifyAbort(5) {
		return
	}

	bh.log("🎯 About to perform active collection for %d computers", len(computers))
	bh.runRemoteStep(6, func() { bh.collectComputerData(6, computers, collector) })
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
				bh.logVerbose("🦘 Skipped %s (already loaded)", filePath)
				continue
			}

			r, err := reader.NewMPReader(filePath)
			if err != nil {
				bh.log("❌ Error opening file %s: %v", filePath, err)
				continue
			}

			numEntries, err := r.ReadLength()
			if err != nil {
				bh.log("❌ Error reading length of %s: %v", filePath, err)
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

		elapsed := time.Since(startTime)
		var percent float64
		if totalEntries > 0 {
			percent = float64(totalProcessed) / float64(totalEntries) * 100.0
		}

		// Calculate metrics
		metrics := calculateProgressMetrics(totalProcessed, totalEntries, startTime, &lastUpdateTime, &lastCount)

		if bh.RemoteCollectionUpdates != nil {
			select {
			case bh.RemoteCollectionUpdates <- RemoteCollectionUpdate{
				Step:      step,
				Processed: totalProcessed,
				Total:     totalEntries,
				Percent:   percent,
				Speed:     metrics.speedText,
				AvgSpeed:  metrics.avgSpeedText,
				ETA:       metrics.etaText,
				Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
			}:
			default:
			}
		}
	}

	// Second pass: process all readers sequentially
	for _, info := range readers {
		if bh.IsAborted() {
			break
		}

		filePath := info.reader.GetPath()
		bh.logVerbose("📦 Loading %s", filePath)

		builder.BState().CacheEntries(info.reader, info.identifier, bh.Logger, bh.IsAborted, progressCallback)

		// Mark this cache as loaded
		builder.BState().MarkCacheLoaded(filePath)

		bh.logVerbose("✅ %s loaded", filePath)
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
			bh.log("❌ Error opening configuration file: %v", err)
			continue
		}
		defer mpReader.Close()

		_, err = mpReader.ReadLength()
		if err != nil {
			bh.log("❌ Error reading length of configuration file: %v", err)
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
				bh.log("❌ Error decoding configuration entry: %v", err)
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

	return targets
}

// CollectRemoteEnterpriseCA sets up encoding and delegates to collectEnterpriseCAData
func (bh *BH) CollectRemoteEnterpriseCA(step int, targets []EnterpriseCACollectionTarget, collector *RemoteCollector) {
	if len(targets) == 0 {
		return
	}

	// Create output file with buffered writer
	remoteCAFile := filepath.Join(bh.ActiveFolder, "RemoteEnterpriseCA.msgpack")
	outFile, err := os.Create(remoteCAFile)
	if err != nil {
		bh.log("❌ Failed to create CA results file: %v", err)
		return
	}
	defer outFile.Close()

	// Use buffered writer for better encoding performance
	bufWriter := bufio.NewWriterSize(outFile, 1024*1024)
	defer bufWriter.Flush()

	encoder := msgpack.NewEncoder(bufWriter)

	bh.collectEnterpriseCAData(step, targets, collector, encoder)
}

// collectEnterpriseCAData collects data from enterprise CAs using worker pool
func (bh *BH) collectEnterpriseCAData(step int, targets []EnterpriseCACollectionTarget, collector *RemoteCollector, encoder *msgpack.Encoder) {
	// Prepare targets - resolve IPs upfront
	for idx := range targets {
		ip := net.ParseIP(targets[idx].DNSHostName)
		if ip != nil {
			targets[idx].IPAddress = targets[idx].DNSHostName
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), config.DNS_LOOKUP_TIMEOUT)
			addrs, err := bh.Resolver.LookupHost(ctx, targets[idx].DNSHostName)
			cancel()
			if err == nil && len(addrs) > 0 {
				targets[idx].IPAddress = addrs[0]
			}
		}
	}

	numWorkers := bh.RemoteWorkers
	timeout := bh.RemoteComputerTimeout

	targetChan := make(chan EnterpriseCACollectionTarget)
	resultChan := make(chan EnterpriseCARemoteCollectionResult, bh.RemoteWriteBuff)

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for target := range targetChan {
				if bh.IsAborted() {
					return
				}

				if target.IPAddress == "" {
					continue
				}

				collectionCtx, collectionCancel := context.WithTimeout(context.Background(), timeout)
				result := collector.CollectRemoteEnterpriseCAWithContext(collectionCtx, target)
				collectionCancel()

				resultChan <- result
			}
		}(i)
	}

	// Process results
	workersDone := make(chan struct{})
	var processedCount int
	var successCount int

	go bh.processEnterpriseCAResults(step, resultChan, workersDone, encoder, targets, &processedCount, &successCount)

	// Feed targets to workers
	go func() {
		for _, target := range targets {
			if bh.IsAborted() {
				break
			}
			targetChan <- target
		}
		close(targetChan)
	}()

	// Wait for workers
	wg.Wait()
	close(resultChan)

	// Wait for result processor
	<-workersDone
}

// processEnterpriseCAResults processes CA collection results from workers
func (bh *BH) processEnterpriseCAResults(
	step int,
	resultChan chan EnterpriseCARemoteCollectionResult,
	workersDone chan struct{},
	encoder *msgpack.Encoder,
	targets []EnterpriseCACollectionTarget,
	processedCount *int,
	successCount *int,
) {
	defer close(workersDone)

	startTime := time.Now()
	lastUpdateTime := startTime
	lastCount := 0

	// Track seen GUIDs to prevent duplicates
	seenGUIDs := make(map[string]bool)

	for res := range resultChan {
		// Encode result only if not seen before,
		// but report progress given the entire set
		// Repeated identifiers are not likely to happen outside of testing,
		// but we handle it just to be safe.
		if !seenGUIDs[res.GUID] {
			seenGUIDs[res.GUID] = true
			if err := encoder.Encode(res); err != nil {
				bh.log("Failed to encode CA result: %v", err)
			}
		}

		*processedCount++

		// Count successes
		if bh.checkAnyCASuccess(res) {
			*successCount++
		}

		elapsed := time.Since(startTime)

		var percent float64
		if len(targets) > 0 {
			percent = float64(*processedCount) / float64(len(targets)) * 100.0
		}

		metrics := calculateProgressMetrics(*processedCount, len(targets), startTime, &lastUpdateTime, &lastCount)

		successText := formatSuccessRate(*successCount, *processedCount)

		if bh.RemoteCollectionUpdates != nil {
			select {
			case bh.RemoteCollectionUpdates <- RemoteCollectionUpdate{
				Step:      step,
				Processed: *processedCount,
				Total:     len(targets),
				Percent:   percent,
				Speed:     metrics.speedText,
				AvgSpeed:  metrics.avgSpeedText,
				Success:   successText,
				ETA:       metrics.etaText,
				Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
			}:
			default:
			}
		}
	}
}

// loadComputerTargets reads computer entries from LDAP msgpack files
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
			bh.log("❌ Error opening computers file: %v", err)
			continue
		}
		defer mpReader.Close()

		length, err := mpReader.ReadLength()
		if err != nil {
			bh.log("❌ Error reading length of computers file: %v", err)
			continue
		}

		readers = append(readers, mpReader)
		totalComputers += length
	}

	startTime := time.Now()
	entryCount := atomic.Int32{}
	validCount := atomic.Int32{}

	// Read entries from LDAP files
	for _, reader := range readers {
		originalEntry := new(ldap.Entry)
		var entry gildap.LDAPEntry

		for i := 0; i < reader.Length(); i++ {
			if bh.IsAborted() {
				break
			}

			*originalEntry = ldap.Entry{}
			if err := reader.ReadEntry(originalEntry); err != nil {
				bh.log("❌ Error decoding computer: %v", err)
				continue
			}

			entry.Init(originalEntry)
			entryCount.Add(1)

			dNSHostName := entry.GetAttrVal("dNSHostName", "")
			sAMAccountName := entry.GetAttrVal("sAMAccountName", "")

			if dNSHostName != "" && sAMAccountName != "" {
				validCount.Add(1)
				targets = append(targets, CollectionTarget{
					SID:                entry.GetSID(),
					DNSHostName:        dNSHostName,
					SamName:            sAMAccountName,
					IsDC:               entry.IsDC(),
					Domain:             entry.GetDomainFromDN(),
					OperatingSystem:    entry.GetAttrVal("operatingSystem", ""),
					PwdLastSet:         gildap.FormatTime2(entry.GetAttrVal("pwdLastSet", "0")),
					LastLogonTimestamp: gildap.FormatTime2(entry.GetAttrVal("lastLogonTimestamp", "0")),
				})
			}

			// Send progress update
			if bh.RemoteCollectionUpdates != nil {
				currentCount := int(entryCount.Load())
				currentValid := int(validCount.Load())
				elapsed := time.Since(startTime)

				var percent float64
				if totalComputers > 0 {
					percent = float64(currentCount) / float64(totalComputers) * 100.0
				}

				successText := formatSuccessRate(currentValid, currentCount)

				select {
				case bh.RemoteCollectionUpdates <- RemoteCollectionUpdate{
					Step:      step,
					Processed: currentCount,
					Total:     totalComputers,
					Percent:   percent,
					Success:   successText,
					Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
				}:
				default:
				}
			}
		}

		if bh.IsAborted() {
			break
		}
	}

	// Send final update
	if bh.RemoteCollectionUpdates != nil {
		finalCount := int(entryCount.Load())
		finalValid := int(validCount.Load())
		elapsed := time.Since(startTime)
		var percent float64
		if totalComputers > 0 {
			percent = float64(finalCount) / float64(totalComputers) * 100.0
		}

		// Calculate average speed
		var avgSpeedText string
		if elapsed.Seconds() > 0 {
			avgRate := float64(finalCount) / elapsed.Seconds()
			avgSpeedText = fmt.Sprintf("%.0f/s", avgRate)
		} else {
			avgSpeedText = "-"
		}

		// Show valid computers as success metric
		successText := formatSuccessRate(finalValid, finalCount)

		bh.RemoteCollectionUpdates <- RemoteCollectionUpdate{
			Step:      step,
			Processed: finalCount,
			Total:     totalComputers,
			Percent:   percent,
			AvgSpeed:  avgSpeedText,
			Success:   successText,
			Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
		}
	}

	return targets
}

// checkComputerAvailability runs availability checks on computers
func (bh *BH) checkComputerAvailability(step int, computers []CollectionTarget, collector *RemoteCollector) []CollectionTarget {
	enabledChecks := bh.RuntimeOptions.GetAvailabilityChecks()

	// If empty map, skip all checks - return all computers
	if len(enabledChecks) == 0 {
		bh.log("🦘 Skipping availability checks (empty list in config)")

		// Mark step as skipped
		if bh.RemoteCollectionUpdates != nil {
			bh.RemoteCollectionUpdates <- RemoteCollectionUpdate{
				Step:      step,
				Processed: len(computers),
				Total:     len(computers),
				Percent:   100.0,
				Success:   fmt.Sprintf("%d/%d (100.0%%)", len(computers), len(computers)),
				Status:    "skipped",
			}
		}

		return computers
	}

	totalComputers := len(computers)
	startTime := time.Now()

	// Counting strategy overview:
	// - Phase 1 (instant checks): Process all computers synchronously
	// - Phase 2 (port scans): Process only computers that passed instant checks in parallel
	// - Total processed = computers that failed instant checks + completed port scans
	// - Available = computers that passed both instant checks AND port scans

	// Step 1: Run instant checks synchronously
	// These are cheap checks (OS version, last logon time, etc.)
	// that filter out obviously unavailable computers
	var afterInstantChecks []CollectionTarget
	for _, computer := range computers {
		ok, errMsg := checkInstantAvailability(
			computer.OperatingSystem,
			computer.PwdLastSet,
			computer.LastLogonTimestamp,
			enabledChecks,
		)

		if ok {
			afterInstantChecks = append(afterInstantChecks, computer)
		} else {
			bh.logVerbose("🦘 [yellow]Skipping %s: %s[-]", computer.DNSHostName, errMsg)
		}
	}

	// If port scan is not enabled, we're done
	if !enabledChecks["smb_port_scan"] {
		// Send final update
		if bh.RemoteCollectionUpdates != nil {
			finalProcessed := totalComputers // All computers were checked via instant checks
			finalAvailable := len(afterInstantChecks)
			elapsed := time.Since(startTime)
			var percent float64
			if totalComputers > 0 {
				percent = 100.0 // All instant checks completed
			}

			successText := formatSuccessRate(finalAvailable, finalProcessed)

			bh.RemoteCollectionUpdates <- RemoteCollectionUpdate{
				Step:      step,
				Processed: finalProcessed,
				Total:     totalComputers,
				Percent:   percent,
				Success:   successText,
				AvgSpeed:  "-",
				Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
			}
		}

		bh.log("✅ Availability checks passed for %d/%d computers", len(afterInstantChecks), totalComputers)
		return afterInstantChecks
	}

	// Step 2: Run port scans concurrently with worker pool
	// Only computers that passed instant checks are port scanned
	var available []CollectionTarget
	availableCount := atomic.Int32{} // Tracks computers that passed port scan

	// Progress tracking: We need to show progress across both phases
	// totalProcessedCount = computers that failed instant checks + port scans completed
	totalProcessedCount := atomic.Int32{}
	totalProcessedCount.Store(int32(totalComputers - len(afterInstantChecks))) // Initialize with instant check failures

	// Create channels for port scan jobs
	jobs := make(chan CollectionTarget, bh.RemoteWorkers*2)
	results := make(chan CollectionTarget, bh.RemoteWorkers*2)

	// Start port scan worker pool
	var wg sync.WaitGroup
	ctx := context.Background()
	for w := 0; w < bh.RemoteWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if bh.IsAborted() {
					continue
				}

				ok, errMsg := collector.smbPortCheck(ctx, job.DNSHostName)
				totalProcessedCount.Add(1) // Increment overall progress (instant failures + port scans done)

				if ok {
					availableCount.Add(1) // Computer passed both instant checks AND port scan
					results <- job
				} else {
					bh.logVerbose("🦘 [yellow]Skipping %s: %s[-]", job.DNSHostName, errMsg)
				}

				// Send progress update
				if bh.RemoteCollectionUpdates != nil {
					currentProcessed := int(totalProcessedCount.Load())
					currentAvailable := int(availableCount.Load())
					elapsed := time.Since(startTime)

					var percent float64
					if totalComputers > 0 {
						percent = float64(currentProcessed) / float64(totalComputers) * 100.0
					}

					successText := formatSuccessRate(currentAvailable, currentProcessed)

					select {
					case bh.RemoteCollectionUpdates <- RemoteCollectionUpdate{
						Step:      step,
						Processed: currentProcessed,
						Total:     totalComputers,
						Percent:   percent,
						Success:   successText,
						Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
					}:
					default:
					}
				}
			}
		}()
	}

	// Start result collector
	done := make(chan struct{})
	var mu sync.Mutex
	go func() {
		for result := range results {
			mu.Lock()
			available = append(available, result)
			mu.Unlock()
		}
		close(done)
	}()

	// Feed port scan jobs to workers
	for _, computer := range afterInstantChecks {
		if bh.IsAborted() {
			break
		}
		jobs <- computer
	}

	close(jobs)
	wg.Wait()
	close(results)
	<-done

	// Send final update
	if bh.RemoteCollectionUpdates != nil {
		finalAvailable := int(availableCount.Load())
		elapsed := time.Since(startTime)

		// All computers were processed (instant checks + port scans)
		finalProcessed := totalComputers

		var percent float64
		if totalComputers > 0 {
			percent = 100.0
		}

		successText := formatSuccessRate(finalAvailable, finalProcessed)

		var avgSpeedText string
		if elapsed.Seconds() > 0 {
			avgRate := float64(finalProcessed) / elapsed.Seconds()
			avgSpeedText = fmt.Sprintf("%.0f/s", avgRate)
		} else {
			avgSpeedText = "-"
		}

		bh.RemoteCollectionUpdates <- RemoteCollectionUpdate{
			Step:      step,
			Processed: finalProcessed,
			Total:     totalComputers,
			Percent:   percent,
			Success:   successText,
			AvgSpeed:  avgSpeedText,
			Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
		}
	}

	bh.log("✅ Availability checks passed for %d/%d computers", len(available), totalComputers)
	return available
}

// performDNSLookups performs DNS lookups on computers and returns those with valid IPs
func (bh *BH) performDNSLookups(step int, computers []CollectionTarget) []CollectionTarget {
	var targets []CollectionTarget
	totalComputers := len(computers)

	startTime := time.Now()
	processedCount := atomic.Int32{}
	successCount := atomic.Int32{}

	// Create channels for job distribution
	jobs := make(chan CollectionTarget, bh.DNSWorkers*2)
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

				ctx, cancel := context.WithTimeout(context.Background(), config.DNS_LOOKUP_TIMEOUT)
				addrs, err := bh.Resolver.LookupHost(ctx, job.DNSHostName)
				cancel()

				processedCount.Add(1)

				if err == nil && len(addrs) > 0 {
					successCount.Add(1)
					// Update with IP address
					job.IPAddress = addrs[0]
					results <- job
				} else {
					bh.logVerbose("🫠 [yellow]Could not resolve %s: %v[-]", job.DNSHostName, err)
				}

				// Send progress update
				if bh.RemoteCollectionUpdates != nil {
					currentProcessed := int(processedCount.Load())
					currentSuccess := int(successCount.Load())
					elapsed := time.Since(startTime)

					var percent float64
					if totalComputers > 0 {
						percent = float64(currentProcessed) / float64(totalComputers) * 100.0
					}

					successText := formatSuccessRate(currentSuccess, currentProcessed)

					select {
					case bh.RemoteCollectionUpdates <- RemoteCollectionUpdate{
						Step:      step,
						Processed: currentProcessed,
						Total:     totalComputers,
						Percent:   percent,
						Success:   successText,
						Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
					}:
					default:
					}
				}
			}
		}()
	}

	// Start result collector
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

	// Feed jobs to workers
	for _, computer := range computers {
		if bh.IsAborted() {
			break
		}
		jobs <- computer
	}

	close(jobs)
	wg.Wait()
	close(results)
	<-done

	// Send final update
	if bh.RemoteCollectionUpdates != nil {
		finalProcessed := int(processedCount.Load())
		finalSuccess := int(successCount.Load())
		elapsed := time.Since(startTime)
		var percent float64
		if totalComputers > 0 {
			percent = float64(finalProcessed) / float64(totalComputers) * 100.0
		}

		successText := formatSuccessRate(finalSuccess, finalProcessed)

		// Calculate average speed
		var avgSpeedText string
		if elapsed.Seconds() > 0 {
			avgRate := float64(finalProcessed) / elapsed.Seconds()
			avgSpeedText = fmt.Sprintf("%.0f/s", avgRate)
		} else {
			avgSpeedText = "-"
		}

		bh.RemoteCollectionUpdates <- RemoteCollectionUpdate{
			Step:      step,
			Processed: finalProcessed,
			Total:     totalComputers,
			Percent:   percent,
			Success:   successText,
			AvgSpeed:  avgSpeedText,
			Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
		}
	}

	return targets
}

// collectComputerData collects data from computers using worker pool
func (bh *BH) collectComputerData(step int, computers []CollectionTarget, collector *RemoteCollector) {
	numWorkers := bh.RemoteWorkers
	timeout := bh.RemoteComputerTimeout

	// Create output file
	remoteResultsFile := filepath.Join(bh.ActiveFolder, "RemoteComputers.msgpack")
	outFile, err := os.Create(remoteResultsFile)
	if err != nil {
		bh.log("❌ Failed to create results file: %v", err)
		return
	}
	defer outFile.Close()

	// Use buffered writer for better encoding performance
	bufWriter := bufio.NewWriterSize(outFile, 1024*1024) // 1MB buffer
	defer bufWriter.Flush()

	encoder := msgpack.NewEncoder(bufWriter)

	// Setup worker pool
	targetChan := make(chan CollectionTarget)
	resultChan := make(chan RemoteCollectionResult, bh.RemoteWriteBuff)

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for target := range targetChan {
				if bh.IsAborted() {
					return
				}

				collectionCtx, collectionCancel := context.WithTimeout(context.Background(), timeout)
				result := collector.CollectRemoteComputerWithContext(collectionCtx, target)
				collectionCancel()

				resultChan <- result
			}
		}(i)
	}

	// Process results
	workersDone := make(chan struct{})
	var processedCount int
	var successCount int

	go bh.processComputerResults(step, resultChan, workersDone, encoder, computers, &processedCount, &successCount)

	// Feed targets to workers
	go func() {
		for _, target := range computers {
			if bh.IsAborted() {
				break
			}
			targetChan <- target
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
			bh.log("✅ Computer results saved to: %s (%s)", remoteResultsFile, formatFileSize(fileInfo.Size()))
		} else {
			bh.log("🫠 [yellow]Problem saving %s: %v[-]", remoteResultsFile, err)
		}
		return
	}

	if fileInfo, err := os.Stat(remoteResultsFile); err == nil {
		bh.log("✅ Computer results saved to: %s (%s)", remoteResultsFile, formatFileSize(fileInfo.Size()))
	} else {
		bh.log("🫠 [yellow]Problem saving %s: %v[-]", remoteResultsFile, err)
	}
}

func (bh *BH) checkAnyComputerSuccess(result RemoteCollectionResult) bool {
	// Kind of a hacky way to check if "any relevant call succeeded"
	// but for now it works :)
	if result.Sessions.Collected {
		return true
	}
	if result.PrivilegedSessions.Collected {
		return true
	}
	if len(result.LocalGroups) > 0 && result.LocalGroups[0].Collected {
		return true
	}
	if result.RegistrySessions.Collected {
		return true
	}
	if len(result.UserRights) > 0 && result.UserRights[0].Collected {
		return true
	}
	if result.NTLMRegistryData.Collected {
		return true
	}
	if result.IsWebClientRunning.Collected {
		return true
	}

	return result.DCRegistryData.CertificateMappingMethods != nil ||
		result.DCRegistryData.StrongCertificateBindingEnforcement != nil ||
		result.DCRegistryData.VulnerableNetlogonSecurityDescriptor != nil
}

func (bh *BH) checkAnyCASuccess(result EnterpriseCARemoteCollectionResult) bool {
	// Check if any CA data collection succeeded
	if result.CARegistryData.CASecurity.Collected {
		return true
	}
	if result.CARegistryData.EnrollmentAgentRestrictions.Collected {
		return true
	}
	if result.CARegistryData.IsUserSpecifiesSanEnabled.Collected {
		return true
	}
	if result.CARegistryData.IsRoleSeparationEnabled.Collected {
		return true
	}
	if len(result.HttpEnrollmentEndpoints) > 0 && result.HttpEnrollmentEndpoints[0].Collected {
		return true
	}
	return false
}

// processComputerResults handles result processing from collection workers
func (bh *BH) processComputerResults(step int, resultChan chan RemoteCollectionResult, done chan struct{}, encoder *msgpack.Encoder,
	computers []CollectionTarget, processedCount, successCount *int) {

	defer close(done)
	startTime := time.Now()
	lastUpdateTime := startTime
	lastCount := 0

	// Track seen SIDs to prevent duplicates
	seenSIDs := make(map[string]bool)

	for res := range resultChan {
		// Encode result only if not seen before
		if !seenSIDs[res.SID] {
			seenSIDs[res.SID] = true
			if err := encoder.Encode(res); err != nil {
				bh.log("Failed to encode result: %v", err)
			}
		}

		*processedCount++

		// Count successes
		if bh.checkAnyComputerSuccess(res) {
			*successCount++
		}

		// Progress reporting
		elapsed := time.Since(startTime)
		metrics := calculateProgressMetrics(*processedCount, len(computers), startTime, &lastUpdateTime, &lastCount)

		progressPercent := float64(*processedCount) / float64(len(computers)) * 100.0

		// Calculate success percentage relative to already-processed entries
		var successPercent float64
		if *processedCount > 0 {
			successPercent = float64(*successCount) / float64(*processedCount) * 100.0
		}

		// Send channel update
		if bh.RemoteCollectionUpdates != nil {
			select {
			case bh.RemoteCollectionUpdates <- RemoteCollectionUpdate{
				Step:      step,
				Processed: *processedCount,
				Total:     len(computers),
				Percent:   progressPercent,
				Speed:     metrics.speedText,
				AvgSpeed:  metrics.avgSpeedText,
				Success:   fmt.Sprintf("%d/%d (%.1f%%)", *successCount, *processedCount, successPercent),
				ETA:       metrics.etaText,
				Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
			}:
			default:
			}
		}
	}
}
