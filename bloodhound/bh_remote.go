package bloodhound

import (
	"context"
	"fmt"
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
	"github.com/Macmod/flashingestor/smb"
	"github.com/go-ldap/ldap/v3"
)

// RemoteCollector executes remote data collection from AD computers and CAs.
type RemoteCollector struct {
	auth                *config.CredentialMgr
	noCrossDomain       bool
	RuntimeOptions      *config.RuntimeOptions
	RemoteMethodTimeout time.Duration
	logger              *core.Logger
}

// NewRemoteCollector creates a collector with the given credentials and options.
func NewRemoteCollector(
	authenticator *config.CredentialMgr,
	runtimeOptions *config.RuntimeOptions,
	methodTimeout time.Duration,
	noCrossDomain bool,
	logger *core.Logger,
) *RemoteCollector {
	return &RemoteCollector{
		auth:                authenticator,
		noCrossDomain:       noCrossDomain,
		RuntimeOptions:      runtimeOptions,
		RemoteMethodTimeout: methodTimeout,
		logger:              logger,
	}
}

type RemoteCollectionUpdate = core.RemoteCollectionUpdate

// getTotalRemoteSteps returns the number of remote collection steps
func (bh *BH) getTotalRemoteSteps() int {
	baseSteps := 1 // Cache Load is always first
	if bh.RuntimeOptions.IsMethodEnabled("gpolocalgroup") {
		baseSteps++ // GPOLocalGroups
	}
	if bh.RuntimeOptions.IsAnyCAMethodEnabled() {
		baseSteps++ // RemoteEnterpriseCAs
	}
	if bh.RuntimeOptions.IsAnyComputerMethodEnabled() {
		baseSteps += 3 // Load Computers, Status Checks, RemoteComputers
	}
	return baseSteps
}

// PerformRemoteCollection gathers data from computers and CAs using RPC and HTTP.
func (bh *BH) PerformRemoteCollection(auth *config.CredentialMgr, noCrossDomain bool) {
	// Initialize builder state (clears old data)
	forestMapPath := filepath.Join(bh.LdapFolder, "ForestDomains.json")
	builder.BState().Init(forestMapPath)

	// Create remote collector with authentication options
	collector := NewRemoteCollector(auth, bh.RuntimeOptions, bh.RemoteMethodTimeout, noCrossDomain, bh.Logger)

	notifyAbort := func(currentStep int) bool {
		if bh.IsAborted() {
			// Mark remaining steps as skipped
			for step := currentStep + 1; step <= bh.getTotalRemoteSteps(); step++ {
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

	currentStep := 1
	bh.runRemoteStep(currentStep, bh.loadRemoteCollectionCache)
	if notifyAbort(currentStep) {
		return
	}
	bh.Logger.Log0("-")

	// GPO local group changes
	if bh.RuntimeOptions.IsMethodEnabled("gpolocalgroup") {
		currentStep++
		targets := builder.BState().GetCachedGPLinks()

		if len(targets) > 0 {
			bh.Logger.Log0("🎯 About to perform GPOLocalGroup collection for %d targets (domains + OUs)", len(targets))
		} else {
			bh.Logger.Log0("🎯 [yellow]No targets found for GPOLocalGroup collection[-]")
		}

		bh.runRemoteStep(currentStep, func(row int) { bh.collectGPOChanges(row, targets, collector) })
		if notifyAbort(currentStep) {
			return
		}

		bh.Logger.Log0("-")
	}

	// Enterprise CAs
	if bh.RuntimeOptions.IsAnyCAMethodEnabled() {
		currentStep++
		enterpriseCAs := bh.loadEnterpriseCATargets()

		if len(enterpriseCAs) > 0 {
			bh.Logger.Log0("🎯 About to perform active collection for %d enterprise CAs", len(enterpriseCAs))
		} else {
			bh.Logger.Log0("🎯 [yellow]No enterprise CAs found to collect[-]")
		}

		bh.runRemoteStep(currentStep, func(row int) { bh.collectRemoteEnterpriseCAs(row, enterpriseCAs, collector) })
		if notifyAbort(currentStep) {
			return
		}

		bh.Logger.Log0("-")
	}

	// Computer collection
	if bh.RuntimeOptions.IsAnyComputerMethodEnabled() {
		// Load computer targets from LDAP
		currentStep++
		var allComputers []CollectionTarget
		bh.runRemoteStep(currentStep, func(row int) { allComputers = bh.loadComputerTargets(row) })
		if notifyAbort(currentStep) {
			return
		}

		bh.Logger.Log0("✅ Found %d valid computers to collect data from", len(allComputers))

		// Create writer manager for both availability checks and collection
		writerManager := newDomainWriterManager(bh.ActiveFolder, "RemoteComputers.msgpack", bh.Logger)
		defer writerManager.Close()

		// Run availability checks
		currentStep++
		var availableComputers []CollectionTarget
		var availabilityStats map[string]int
		bh.runRemoteStep(currentStep, func(row int) {
			availableComputers, availabilityStats = bh.checkComputerAvailability(row, allComputers, collector, writerManager)
		})
		if notifyAbort(currentStep) {
			return
		}

		// Log availability check results with statistics
		if len(availableComputers) == len(allComputers) {
			bh.Logger.Log0("✅ [green]Availability checks passed for all %d computers[-]", len(allComputers))
		} else if len(availableComputers) > 0 {
			bh.Logger.Log0("✅ [green]Availability checks passed for %d/%d computers[-]", len(availableComputers), len(allComputers))
			for reason, count := range availabilityStats {
				bh.Logger.Log0("   [yellow]%d skipped: %s[-]", count, reason)
			}
		} else {
			bh.Logger.Log0("🫠 [yellow]No computers passed availability checks[-]")
			for reason, count := range availabilityStats {
				bh.Logger.Log0("   [yellow]%d skipped: %s[-]", count, reason)
			}
		}

		// Collect computer data
		currentStep++

		if len(availableComputers) > 0 {
			bh.Logger.Log0("🎯 About to perform active collection for %d computers", len(availableComputers))
		} else {
			bh.Logger.Log0("🎯 [yellow]No computers found to collect[-]")
		}

		var processedCount, successCount int
		bh.runRemoteStep(currentStep, func(row int) {
			processedCount, successCount = bh.collectComputerData(row, availableComputers, collector, writerManager)
		})

		// Output final collection message
		if successCount > 0 {
			bh.Logger.Log0("✅ [green]Completed active collection for %d/%d computers (%d successful)[-]",
				processedCount, len(availableComputers), successCount)
		} else {
			bh.Logger.Log0("🫠 [yellow]Completed active collection for %d/%d computers (none successful)[-]",
				processedCount, len(availableComputers))
		}

		bh.Logger.Log0("-")
	}
}

// runRemoteStep runs a remote collection step and sends progress events
func (bh *BH) runRemoteStep(row int, stepFunc func(int)) {
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
	stepFunc(row)
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

	neededCaches := []string{"domains", "ous", "trusts", "users", "groups", "computers", "gpos", "configuration"}

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
				bh.Logger.Log1("🦘 Skipped %s (already loaded)", filePath)
				continue
			}

			r, err := reader.NewMPReader(filePath)
			if err != nil {
				bh.Logger.Log0("❌ Error opening file %s: %v", filePath, err)
				continue
			}

			numEntries, err := r.ReadLength()
			if err != nil {
				bh.Logger.Log0("❌ Error reading length of %s: %v", filePath, err)
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
		bh.Logger.Log1("📦 Loading %s", filePath)

		// TODO: Only store entries for GPO collection if the method is enabled
		builder.BState().CacheEntries(info.reader, info.identifier, bh.Logger, bh.IsAborted, progressCallback)

		// Mark this cache as loaded
		builder.BState().MarkCacheLoaded(filePath)

		bh.Logger.Log1("✅ %s loaded", filePath)
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
			bh.Logger.Log0("❌ Error opening configuration file: %v", err)
			continue
		}
		defer mpReader.Close()

		_, err = mpReader.ReadLength()
		if err != nil {
			bh.Logger.Log0("❌ Error reading length of configuration file: %v", err)
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
				bh.Logger.Log0("❌ Error decoding configuration entry: %v", err)
				continue
			}

			entry.Init(originalEntry)

			objectClasses := entry.GetAttrVals("objectClass", []string{})
			if slices.Contains(objectClasses, "pKIEnrollmentService") {
				caName := entry.GetAttrVal("name", "")
				dNSHostName := entry.GetAttrVal("dNSHostName", "")
				domain := entry.GetDomainFromDN()
				guid := entry.GetGUID()

				if caName != "" && dNSHostName != "" && domain != "" && guid != "" {
					targets = append(targets, EnterpriseCACollectionTarget{
						GUID:        guid,
						DN:          entry.DN,
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

// collectRemoteEnterpriseCA sets up encoding and delegates to collectEnterpriseCAData
func (bh *BH) collectRemoteEnterpriseCAs(step int, targets []EnterpriseCACollectionTarget, collector *RemoteCollector) {
	if len(targets) == 0 {
		return
	}

	writerManager := newDomainWriterManager(bh.ActiveFolder, "RemoteEnterpriseCA.msgpack", bh.Logger)
	defer writerManager.Close()

	bh.collectEnterpriseCAData(step, targets, collector, writerManager)
}

// collectEnterpriseCAData collects data from enterprise CAs using worker pool
func (bh *BH) collectEnterpriseCAData(step int, targets []EnterpriseCACollectionTarget, collector *RemoteCollector,
	writerManager *domainWriterManager) {
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

				startTime := time.Now()
				collectionCtx, collectionCancel := context.WithTimeout(context.Background(), timeout)
				result, ok := collector.CollectRemoteEnterpriseCAWithContext(collectionCtx, target)
				collectionCancel()
				if !ok {
					bh.Logger.Log1("📋 [red][%s[] EnterpriseCA timeout after %v[-]", target.DNSHostName, time.Since(startTime).Round(time.Millisecond))
				}

				// Always send results (complete or partial)
				// The processEnterpriseCAResults will filter empty results
				resultChan <- result
			}
		}(i)
	}

	// Process results
	workersDone := make(chan struct{})
	var processedCount int
	var successCount int

	go bh.processEnterpriseCAResults(step, resultChan, workersDone, writerManager, targets, &processedCount, &successCount)

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

	if successCount > 0 {
		bh.Logger.Log0("✅ [green]Completed data collection for %d/%d enterprise CAs (%d successful)[-]", processedCount, len(targets), successCount)
	} else {
		bh.Logger.Log0("🫠 [yellow]Completed data collection for %d/%d enterprise CAs (none successful)[-]", processedCount, len(targets))
	}
}

// processEnterpriseCAResults processes CA collection results from workers
func (bh *BH) processEnterpriseCAResults(
	step int,
	resultChan chan EnterpriseCARemoteCollectionResult,
	workersDone chan struct{},
	writerManager *domainWriterManager,
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
		*processedCount++

		// Encode result only if not seen before AND has successful data,
		// but report progress given the entire set
		// Repeated identifiers are not likely to happen outside of testing,
		// but we handle it just to be safe.
		if !seenGUIDs[res.GUID] {
			seenGUIDs[res.GUID] = true

			// Count successes
			hasSuccess := bh.checkAnyCASuccess(res)
			if hasSuccess {
				*successCount++
			}

			// Only write if we have actual data
			if hasSuccess {
				// Get domain from DN
				domain := gildap.DistinguishedNameToDomain(res.DN)
				if domain == "" {
					bh.Logger.Log0("🫠 [yellow]Could not determine domain from DN '%s' for GUID %s, skipping[-]", res.DN, res.GUID)
				} else {
					// Get domain-specific writer
					writer, err := writerManager.Get(domain)
					if err != nil {
						bh.Logger.Log0("❌ Failed to get writer for domain %s: %v", domain, err)
					} else {
						if err := writer.encoder.Encode(res); err != nil {
							bh.Logger.Log0("Failed to encode CA result: %v", err)
						}
					}
				}
			}
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
			bh.Logger.Log0("❌ Error opening computers file: %v", err)
			continue
		}
		defer mpReader.Close()

		length, err := mpReader.ReadLength()
		if err != nil {
			bh.Logger.Log0("❌ Error reading length of computers file: %v", err)
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
				bh.Logger.Log0("❌ Error decoding computer: %v", err)
				continue
			}

			entry.Init(originalEntry)
			entryCount.Add(1)

			dNSHostName := entry.GetAttrVal("dNSHostName", "")
			sAMAccountName := entry.GetAttrVal("sAMAccountName", "")
			sid := entry.GetSID()

			if dNSHostName != "" && sAMAccountName != "" && sid != "" {
				validCount.Add(1)
				targets = append(targets, CollectionTarget{
					SID:                sid,
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
// Returns available computers and a map of error reasons to counts
// Writes unavailable computers to writerManager with Status.Error filled
func (bh *BH) checkComputerAvailability(step int, computers []CollectionTarget, collector *RemoteCollector,
	writerManager *domainWriterManager) ([]CollectionTarget, map[string]int) {
	enabledChecks := bh.RuntimeOptions.GetAvailabilityChecks()
	failureStats := make(map[string]int)
	var statsMu sync.Mutex

	// If empty map, skip all checks - return all computers
	if len(enabledChecks) == 0 {
		bh.Logger.Log0("🦘 Skipping availability checks (empty list in config)")

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

		return computers, failureStats
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
			bh.Logger.Log1("🦘 [yellow][%s[] Skipped Computer: %s[-]", computer.DNSHostName, errMsg)

			// Track failure reason
			failureStats[errMsg]++

			// Write unavailable computer with error status
			errStatus := builder.ComputerStatus{
				Connectable: false,
				Error:       errMsg,
			}
			result := RemoteCollectionResult{
				SID:    computer.SID,
				Status: &errStatus,
			}

			domain := getDomainFromComputerSID(computer.SID)
			if domain != "" {
				writer, err := writerManager.Get(domain)
				if err == nil {
					writer.encoder.Encode(result)
				}
			}
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

		return afterInstantChecks, failureStats
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
					bh.Logger.Log1("🦘 [yellow][%s[] Skipped Computer: %s[-]", job.DNSHostName, errMsg)

					// Track failure reason
					statsMu.Lock()
					failureStats[errMsg]++
					statsMu.Unlock()

					// Write unavailable computer with error status
					errStatus := builder.ComputerStatus{
						Connectable: false,
						Error:       errMsg,
					}
					result := RemoteCollectionResult{
						SID:    job.SID,
						Status: &errStatus,
					}

					domain := getDomainFromComputerSID(job.SID)
					if domain != "" {
						writer, err := writerManager.Get(domain)
						if err == nil {
							writer.encoder.Encode(result)
						}
					}
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

	return available, failureStats
}

// collectComputerData collects data from computers using worker pool
// Returns (processedCount, successCount)
func (bh *BH) collectComputerData(step int, computers []CollectionTarget,
	collector *RemoteCollector, writerManager *domainWriterManager) (int, int) {
	numWorkers := bh.RemoteWorkers
	timeout := bh.RemoteComputerTimeout

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

				startTime := time.Now()
				collectionCtx, collectionCancel := context.WithTimeout(context.Background(), timeout)
				result, ok := collector.CollectRemoteComputerWithContext(collectionCtx, target)
				collectionCancel()
				if !ok {
					attempted := result.CountAttemptedMethods()
					total := result.GetTotalMethods(collector.RuntimeOptions, target.IsDC)
					bh.Logger.Log1("💻 [red][%s[] Computer timeout after %v (%d/%d methods ran)[-]",
						target.DNSHostName, time.Since(startTime).Round(time.Millisecond), attempted, total)
				}

				// Always send results (complete or partial)
				// The processComputerResults filter will discard empty results
				resultChan <- result
			}
		}(i)
	}

	// Process results
	workersDone := make(chan struct{})
	var processedCount int
	var successCount int

	go bh.processComputerResults(step, resultChan, workersDone, writerManager, computers, &processedCount, &successCount)

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

	return processedCount, successCount
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
	if result.SMBInfo != nil && result.SMBInfo.Collected {
		return true
	}
	if result.LdapServices.HasLdap || result.LdapServices.HasLdaps ||
		result.LdapServices.IsChannelBindingRequired.Collected ||
		result.LdapServices.IsSigningRequired.Collected {
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
func (bh *BH) processComputerResults(step int, resultChan chan RemoteCollectionResult, done chan struct{},
	writerManager *domainWriterManager, computers []CollectionTarget, processedCount, successCount *int) {

	defer close(done)
	startTime := time.Now()
	lastUpdateTime := startTime
	lastCount := 0

	// Track seen SIDs to prevent duplicates
	seenSIDs := make(map[string]bool)

	for res := range resultChan {
		*processedCount++

		// Encode result only if not seen before AND has successful data
		success := bh.checkAnyComputerSuccess(res)
		if !seenSIDs[res.SID] {
			seenSIDs[res.SID] = true

			// Only write if we have actual data
			if success {
				*successCount++

				// Get domain for this SID
				domain := getDomainFromComputerSID(res.SID)
				if domain == "" {
					bh.Logger.Log0("🫠 [yellow]Could not determine domain for SID %s, skipping[-]", res.SID)
				} else {
					// Get domain-specific writer
					writer, err := writerManager.Get(domain)
					if err != nil {
						bh.Logger.Log0("❌ Failed to get writer for domain %s: %v", domain, err)
					} else {
						if err := writer.encoder.Encode(res); err != nil {
							bh.Logger.Log0("Failed to encode result: %v", err)
						}
					}
				}
			}
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

// collectGPOChanges collects GPO local group changes for all OUs and Domains
// This reads from the existing LDAP ingestion (no LDAP queries)
func (bh *BH) collectGPOChanges(step int, targets map[string]builder.GPLinkEntry, collector *RemoteCollector) {
	// Clear the GPO action cache for this collection run
	gpoActionCacheMu.Lock()
	gpoActionCache = make(map[string][]GroupAction)
	gpoActionCacheMu.Unlock()

	writerManager := newDomainWriterManager(bh.ActiveFolder, "RemoteGPOChanges.msgpack", bh.Logger)
	defer writerManager.Close()

	startTime := time.Now()

	// Create shared SMB reader for all workers
	smbReader := smb.NewFileReader(collector.auth)
	defer smbReader.Close() // Close all pooled connections when done

	// Process with worker pool
	totalTargets := len(targets)
	numWorkers := bh.RemoteWorkers
	resultChan := make(chan GPOLocalGroupsCollectionResult, bh.RemoteWriteBuff)
	taskChan := make(chan struct {
		DN string
		builder.GPLinkEntry
	}, totalTargets)

	var wg sync.WaitGroup
	var processedCount atomic.Int32
	var successCount atomic.Int32
	var targetsWithChanges atomic.Int32

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for task := range taskChan {
				if bh.IsAborted() {
					return
				}

				gpoChanges, err := collector.ReadGPOLocalGroupsForTarget(task.DN, task.GPLink, smbReader)

				processedCount.Add(1)
				if err == nil {
					successCount.Add(1)
				} else {
					bh.Logger.Log1("❌ [red][%s[] GPOLocalGroups: %v[-]", task.DN, err)
				}

				hasChanges := !gpoChanges.IsEmpty()

				if hasChanges {
					targetsWithChanges.Add(1)
					bh.Logger.Log1("🎡 [green][%s[] Found GPOLocalGroup changes: %d admins, %d RDP, %d DCOM, %d PSRemote[-]",
						task.DN,
						len(gpoChanges.LocalAdmins),
						len(gpoChanges.RemoteDesktopUsers),
						len(gpoChanges.DcomUsers),
						len(gpoChanges.PSRemoteUsers))
				} else {
					bh.Logger.Log2("🎡 [%s[] No GPOLocalGroup changes found", task.DN)
				}

				// Send result to channel
				resultChan <- GPOLocalGroupsCollectionResult{
					DN:         task.DN,
					ObjectType: task.ObjectType,
					GPOChanges: *gpoChanges,
				}
			}
		}()
	}

	// Start result writer with progress tracking
	var writerWg sync.WaitGroup
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		lastUpdateTime := startTime
		lastCount := 0
		processedInWriter := 0

		for result := range resultChan {
			if bh.IsAborted() {
				return
			}

			processedInWriter++

			// Only write if there are actual changes
			if !result.GPOChanges.IsEmpty() {
				// Extract domain from DN
				domain := gildap.DistinguishedNameToDomain(result.DN)
				if domain == "" {
					bh.Logger.Log0("🫠 [yellow]Could not extract domain from DN: %s, skipping entry[-]", result.DN)
				} else {
					// Get or create encoder for this domain
					writer, err := writerManager.Get(domain)
					if err != nil {
						bh.Logger.Log0("❌ Error getting writer for domain %s: %v", domain, err)
					} else {
						if err := writer.encoder.Encode(&result); err != nil {
							bh.Logger.Log0("❌ Error encoding GPO changes entry: %v", err)
						}
					}
				}
			}

			// Send progress update
			processed := int(processedCount.Load())
			success := int(successCount.Load())
			elapsed := time.Since(startTime)
			var percent float64
			if totalTargets > 0 {
				percent = float64(processed) / float64(totalTargets) * 100.0
			}

			metrics := calculateProgressMetrics(processed, totalTargets, startTime, &lastUpdateTime, &lastCount)

			if bh.RemoteCollectionUpdates != nil {
				update := RemoteCollectionUpdate{
					Step:      step,
					Processed: processed,
					Total:     totalTargets,
					Percent:   percent,
					Speed:     metrics.speedText,
					AvgSpeed:  metrics.avgSpeedText,
					Success:   formatSuccessRate(success, processed),
					ETA:       metrics.etaText,
					Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
				}

				bh.RemoteCollectionUpdates <- update
			}
		}
	}()

	// Feed tasks
	go func() {
		for dn, target := range targets {
			if bh.IsAborted() {
				break
			}
			// Create a task with DN from the map key
			taskChan <- struct {
				DN string
				builder.GPLinkEntry
			}{
				DN:          dn,
				GPLinkEntry: target,
			}
		}
		close(taskChan)
	}()

	// Wait for workers to finish
	wg.Wait()
	close(resultChan)

	// Wait for writer to finish
	writerWg.Wait()

	finalMessageStr := "✅ [green]Completed GPOLocalGroup collection for %d/%d targets"
	numChanges := targetsWithChanges.Load()
	if numChanges > 0 {
		if numChanges == 1 {
			finalMessageStr += " (1 target with changes)"
		} else {
			finalMessageStr += fmt.Sprintf(" (%d targets with changes)", numChanges)
		}
	} else {
		finalMessageStr += " (none had changes)"
	}
	finalMessageStr += "[-]"

	bh.Logger.Log0(finalMessageStr, successCount.Load(), totalTargets)
}
