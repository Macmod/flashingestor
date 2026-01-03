package bloodhound

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/config"
	gildap "github.com/Macmod/flashingestor/ldap"
	"github.com/Macmod/flashingestor/reader"
	"github.com/Macmod/flashingestor/ui"
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

// PerformRemoteCollection gathers data from computers and CAs using RPC and HTTP.
func (bh *BH) PerformRemoteCollection(auth *config.CredentialMgr) {
	// Initialize remote collection UI
	bh.UIApp.SetupRemoteCollectionTable()

	var spinner *ui.Spinner
	spinner = ui.NewSingleTableSpinner(bh.UIApp, bh.UIApp.GetRemoteCollectTable(), 0)
	spinner.Start()
	defer spinner.Stop()

	// Initialize builder state
	forestMapPath := filepath.Join(bh.LdapFolder, "ForestDomains.json")
	builder.BState().Init(forestMapPath)

	// Create remote collector with authentication options
	collector := NewRemoteCollector(auth, bh.RuntimeOptions)

	bh.runRemoteStep(spinner, 1, func() { bh.loadRemoteCollectionCache() })
	if bh.IsAborted() {
		return
	}

	// Collect from Enterprise CAs
	enterpriseCAs := bh.loadEnterpriseCATargets()
	if bh.IsAborted() {
		return
	}

	bh.collectEnterpriseCAData(spinner, enterpriseCAs, collector)
	if bh.IsAborted() {
		return
	}

	// Collect from computers
	computers := bh.loadComputerTargets(spinner)
	bh.Log <- fmt.Sprintf("🎯 About to perform active collection for %d computers", len(computers))
	bh.collectComputerData(spinner, computers, collector)
}

// runRemoteStep runs a remote collection step and updates UI
func (bh *BH) runRemoteStep(spinner *ui.Spinner, row int, stepFunc func()) {
	if bh.IsAborted() {
		return
	}

	if spinner != nil {
		spinner.SetRunningRow(row)
	}
	bh.updateRemoteRow(row, "", "-", "-", "-", "-", "-", "-", "-")

	startTime := time.Now()
	stepFunc()
	elapsed := time.Since(startTime)

	if bh.IsAborted() {
		if spinner != nil {
			spinner.SetDone(row)
		}
		bh.updateRemoteRow(row, "[red]× Aborted", "", "", "-", "", "-", "-", elapsed.Round(time.Second).String())
		return
	}

	if spinner != nil {
		spinner.SetDone(row)
	}
	bh.updateRemoteRow(row, "[green]✓ Done", "", "", "-", "", "-", "-", elapsed.Round(time.Second).String())
}

// loadRemoteCollectionCache loads necessary caches for remote collection
func (bh *BH) loadRemoteCollectionCache() {
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
				bh.Log <- fmt.Sprintf("🤷🏼 Skipped %s (already loaded)", filePath)
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

		elapsed := time.Since(startTime)
		var processedText string
		var percentText string
		var speedText string
		var avgSpeedText string
		var etaText string

		if totalEntries > 0 {
			if totalProcessed >= totalEntries {
				processedText = fmt.Sprintf("[green]%d/%d[-]", totalProcessed, totalEntries)
			} else {
				processedText = fmt.Sprintf("[blue]%d/%d[-]", totalProcessed, totalEntries)
			}
			percentage := float64(totalProcessed) / float64(totalEntries) * 100.0
			if percentage >= 100.0 {
				percentText = fmt.Sprintf("[green]%.1f%%[-]", percentage)
			} else {
				percentText = fmt.Sprintf("[blue]%.1f%%[-]", percentage)
			}
		} else {
			processedText = fmt.Sprintf("%d", totalProcessed)
			percentText = "-"
		}

		// Calculate speed (items/sec)
		now := time.Now()
		timeSinceLastUpdate := now.Sub(lastUpdateTime).Seconds()
		if timeSinceLastUpdate > 0 && totalProcessed > lastCount {
			currentSpeed := float64(totalProcessed-lastCount) / timeSinceLastUpdate
			speedText = fmt.Sprintf("%.0f/s", currentSpeed)
			lastUpdateTime = now
			lastCount = totalProcessed
		} else {
			speedText = "-"
		}

		// Calculate average speed
		if totalProcessed > 0 && elapsed.Seconds() > 0 {
			avgSpeed := float64(totalProcessed) / elapsed.Seconds()
			avgSpeedText = fmt.Sprintf("%.0f/s", avgSpeed)

			// Calculate ETA
			if totalEntries > 0 && totalProcessed < totalEntries {
				remaining := totalEntries - totalProcessed
				etaSeconds := float64(remaining) / avgSpeed
				etaDuration := time.Duration(etaSeconds * float64(time.Second))
				etaText = etaDuration.Round(time.Second).String()
			} else {
				etaText = "-"
			}
		} else {
			avgSpeedText = "-"
			etaText = "-"
		}

		bh.UIApp.UpdateRemoteCollectionRow(1, "", processedText, percentText, speedText, avgSpeedText, "-", etaText, elapsed.Round(time.Second).String())
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

// updateRemoteRow is a helper to update remote collection row
func (bh *BH) updateRemoteRow(row int, status, processed, percent, speed, avgSpeed, success, eta, elapsed string) {
	bh.UIApp.UpdateRemoteCollectionRow(row, status, processed, percent, speed, avgSpeed, success, eta, elapsed)
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
func (bh *BH) collectEnterpriseCAData(spinner *ui.Spinner, targets []EnterpriseCACollectionTarget, collector *RemoteCollector) {
	bh.Log <- fmt.Sprintf("🎯 About to perform active collection for %d enterprise CAs", len(targets))

	if spinner != nil {
		spinner.SetRunningRow(2)
	}
	bh.updateRemoteRow(2, "", "0", "-", "-", "-", "0", "-", "-")

	startTime := time.Now()
	lastUpdateTime := startTime
	lastCount := 0
	successCount := 0
	caResults := make(map[string]EnterpriseCARemoteCollectionResult)

	for idx, caTarget := range targets {
		if bh.IsAborted() {
			elapsed := time.Since(startTime)
			if spinner != nil {
				spinner.SetDone(2)
			}
			bh.updateRemoteRow(2, "[red]× Aborted", "", "", "-", "", "", "-", elapsed.Round(time.Second).String())
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

		var processedText string
		var percentText string
		var speedText string
		var avgSpeedText string
		var successText string
		var etaText string

		if processedCount == len(targets) {
			processedText = fmt.Sprintf("[green]%d/%d[-]", processedCount, len(targets))
		} else {
			processedText = fmt.Sprintf("[blue]%d/%d[-]", processedCount, len(targets))
		}
		percentage := float64(processedCount) / float64(len(targets)) * 100.0
		if percentage >= 100.0 {
			percentText = fmt.Sprintf("[green]%.1f%%[-]", percentage)
		} else {
			percentText = fmt.Sprintf("[blue]%.1f%%[-]", percentage)
		}

		// Calculate speed
		now := time.Now()
		timeSinceLastUpdate := now.Sub(lastUpdateTime).Seconds()
		if timeSinceLastUpdate > 0 && processedCount > lastCount {
			currentSpeed := float64(processedCount-lastCount) / timeSinceLastUpdate
			speedText = fmt.Sprintf("%.1f/s", currentSpeed)
			lastUpdateTime = now
			lastCount = processedCount
		} else {
			speedText = "-"
		}

		// Calculate average speed
		if processedCount > 0 && elapsed.Seconds() > 0 {
			avgSpeed := float64(processedCount) / elapsed.Seconds()
			avgSpeedText = fmt.Sprintf("%.1f/s", avgSpeed)

			// Calculate ETA
			if processedCount < len(targets) {
				remaining := len(targets) - processedCount
				etaSeconds := float64(remaining) / avgSpeed
				etaDuration := time.Duration(etaSeconds * float64(time.Second))
				etaText = etaDuration.Round(time.Second).String()
			} else {
				etaText = "-"
			}
		} else {
			avgSpeedText = "-"
			etaText = "-"
		}

		successPercent := float64(successCount) / float64(len(targets)) * 100.0
		successText = fmt.Sprintf("%d/%d (%.1f%%)", successCount, len(targets), successPercent)

		bh.updateRemoteRow(2, "", processedText, percentText, speedText, avgSpeedText, successText, etaText, elapsed.Round(time.Second).String())
	}

	// Update final status
	elapsed := time.Since(startTime)
	if spinner != nil {
		spinner.SetDone(2)
	}

	successPercent := 100.0
	var processedText, percentText, successText, avgSpeedText string

	if len(targets) > 0 {
		successPercent = float64(successCount) / float64(len(targets)) * 100.0
		processedText = fmt.Sprintf("[green]%d/%d[-]", len(targets), len(targets))
		percentText = "[green]100.0%[-]"
		successText = fmt.Sprintf("%d/%d (%.1f%%)", successCount, len(targets), successPercent)
		avgSpeed := float64(len(targets)) / elapsed.Seconds()
		avgSpeedText = fmt.Sprintf("%.1f/s", avgSpeed)
	} else {
		processedText = "-"
		percentText = "-"
		successText = "-"
		avgSpeedText = "-"
	}

	bh.updateRemoteRow(2, "[green]✓ Done",
		processedText,
		percentText,
		"-",
		avgSpeedText,
		successText,
		"-",
		elapsed.Round(time.Second).String())

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
func (bh *BH) loadComputerTargets(spinner *ui.Spinner) []CollectionTarget {
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

	if spinner != nil {
		spinner.SetRunningRow(3)
	}
	bh.updateRemoteRow(3, "", fmt.Sprintf("0/%d", totalComputers), "-", "-", "-", "-", "-", "0s")

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
					bh.Log <- fmt.Sprintf("[yellow]🫠 Could not resolve %s: %v[-]", job.dNSHostName, err)
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
		lastCountLocal := int32(0)

		for {
			select {
			case <-progressDone:
				return
			case <-ticker.C:
				currentCount := entryCount.Load()
				elapsed := time.Since(startTime)

				var processedText string
				var percentText string
				var speedText string
				var avgSpeedText string
				var successText string
				var etaText string

				if totalComputers > 0 {
					if int(currentCount) == totalComputers {
						processedText = fmt.Sprintf("[green]%d/%d[-]", currentCount, totalComputers)
					} else {
						processedText = fmt.Sprintf("[blue]%d/%d[-]", currentCount, totalComputers)
					}
					percentage := float64(currentCount) / float64(totalComputers) * 100.0
					if percentage >= 100.0 {
						percentText = fmt.Sprintf("[green]%.1f%%[-]", percentage)
					} else {
						percentText = fmt.Sprintf("[blue]%.1f%%[-]", percentage)
					}
				} else {
					processedText = strconv.Itoa(int(currentCount))
					percentText = "-"
				}

				// Calculate speed
				now := time.Now()
				timeSinceLastUpdate := now.Sub(lastUpdateTime).Seconds()
				if timeSinceLastUpdate > 0 && currentCount > lastCountLocal {
					currentSpeed := float64(currentCount-lastCountLocal) / timeSinceLastUpdate
					speedText = fmt.Sprintf("%.1f/s", currentSpeed)
					lastUpdateTime = now
					lastCountLocal = currentCount
				} else {
					speedText = "-"
				}

				// Calculate average speed
				if currentCount > 0 && elapsed.Seconds() > 0 {
					avgSpeed := float64(currentCount) / elapsed.Seconds()
					avgSpeedText = fmt.Sprintf("%.1f/s", avgSpeed)

					// Calculate ETA
					if totalComputers > 0 && int(currentCount) < totalComputers {
						remaining := totalComputers - int(currentCount)
						etaSeconds := float64(remaining) / avgSpeed
						etaDuration := time.Duration(etaSeconds * float64(time.Second))
						etaText = etaDuration.Round(time.Second).String()
					} else {
						etaText = "-"
					}
				} else {
					avgSpeedText = "-"
					etaText = "-"
				}

				currentSuccess := successCount.Load()
				if currentCount > 0 {
					successPercent := float64(currentSuccess) / float64(currentCount) * 100.0
					successText = fmt.Sprintf("%d/%d (%.1f%%)", currentSuccess, currentCount, successPercent)
				} else {
					successText = "0/0"
				}

				bh.updateRemoteRow(3, "", processedText, percentText, speedText, avgSpeedText, successText, etaText, elapsed.Round(time.Second).String())
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

	elapsed := time.Since(startTime)

	if bh.IsAborted() {
		if spinner != nil {
			spinner.SetDone(3)
		}
		bh.updateRemoteRow(3, "[red]× Aborted", "", "", "-", "", "", "-", elapsed.Round(time.Second).String())
		return targets
	}

	finalEntryCount := entryCount.Load()
	finalSuccessCount := successCount.Load()
	avgRate := float64(finalEntryCount) / elapsed.Seconds()
	successPercent := 100.0
	if finalEntryCount > 0 {
		successPercent = float64(finalSuccessCount) / float64(finalEntryCount) * 100.0
	}

	if spinner != nil {
		spinner.SetDone(3)
	}

	bh.updateRemoteRow(3, "[green]✓ Done",
		"",
		"",
		"-",
		fmt.Sprintf("%.1f/s", avgRate),
		fmt.Sprintf("%d/%d (%.1f%%)", finalSuccessCount, finalEntryCount, successPercent),
		"-",
		elapsed.Round(time.Second).String())

	return targets
}

// collectComputerData collects data from computers using worker pool
func (bh *BH) collectComputerData(spinner *ui.Spinner, computers []CollectionTarget, collector *RemoteCollector) {
	if spinner != nil {
		spinner.SetRunningRow(4)
	}
	bh.updateRemoteRow(4, "", "0", "-", "-", "-", "0", "-", "-")

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

	go bh.processComputerResults(resultChan, workersDone, encoder, &encoderMu, computers, &processedCount, &successCount, &finalAvgRate, &finalElapsed)

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
		if spinner != nil {
			spinner.SetDone(4)
		}
		bh.updateRemoteRow(4, "[red]× Aborted", "", "", "-", "", "", "-", finalElapsed.Round(time.Second).String())
		if fileInfo, err := os.Stat(remoteResultsFile); err == nil {
			bh.Log <- fmt.Sprintf("✅ Computer results saved to: %s (%s)", remoteResultsFile, formatFileSize(fileInfo.Size()))
		} else {
			bh.Log <- fmt.Sprintf("🫠 [yellow]Problem saving %s: %v[-]", remoteResultsFile, err)
		}
		return
	}

	// Update final status
	bh.finalizeComputerCollection(spinner, len(computers), successCount, finalElapsed)
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
func (bh *BH) processComputerResults(resultChan chan struct {
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

			var processedText, percentText string
			if *processedCount == len(computers) {
				processedText = fmt.Sprintf("[green]%d/%d[-]", *processedCount, len(computers))
			} else {
				processedText = fmt.Sprintf("[blue]%d/%d[-]", *processedCount, len(computers))
			}
			if progressPercent >= 100.0 {
				percentText = fmt.Sprintf("[green]%.1f%%[-]", progressPercent)
			} else {
				percentText = fmt.Sprintf("[blue]%.1f%%[-]", progressPercent)
			}

			bh.updateRemoteRow(4, "",
				processedText,
				percentText,
				fmt.Sprintf("%.1f/s", instRate),
				fmt.Sprintf("%.1f/s", avgRate),
				fmt.Sprintf("%d/%d (%.1f%%)", *successCount, len(computers), successPercent),
				eta.Round(time.Second).String(),
				elapsed.Round(time.Second).String())
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
func (bh *BH) finalizeComputerCollection(spinner *ui.Spinner, total, success int, elapsed time.Duration) {
	if spinner != nil {
		spinner.SetDone(4)
	}

	successPercent := 0.0
	var processedText, percentText, successText string

	if total > 0 {
		successPercent = float64(success) / float64(total) * 100.0
		processedText = fmt.Sprintf("[green]%d/%d[-]", total, total)
		percentText = "[green]100.0%[-]"
		successText = fmt.Sprintf("%d/%d (%.1f%%)", success, total, successPercent)
	} else {
		processedText = "-"
		percentText = "-"
		successText = "-"
	}

	bh.updateRemoteRow(4, "[green]✓ Done",
		processedText,
		percentText,
		"-",
		"",
		successText,
		"-",
		elapsed.Round(time.Second).String())
}
