package bloodhound

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	//"sync"
	"time"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/core"
	gildap "github.com/Macmod/flashingestor/ldap"
	"github.com/Macmod/flashingestor/reader"
	"github.com/go-ldap/ldap/v3"
	"github.com/vmihailenco/msgpack"
)

type ConversionUpdate = core.ConversionUpdate

// progressMetrics holds calculated progress metrics
type progressMetrics struct {
	speedText    string
	avgSpeedText string
	etaText      string
}

// calculateProgressMetrics computes speed, average speed, and ETA for progress updates
func calculateProgressMetrics(currentCount, totalCount int, startTime time.Time, lastUpdateTime *time.Time, lastCount *int) progressMetrics {
	// Calculate current speed
	var speedText string
	now := time.Now()
	timeSinceLastUpdate := now.Sub(*lastUpdateTime).Seconds()
	if timeSinceLastUpdate > 0 && currentCount > *lastCount {
		currentSpeed := float64(currentCount-*lastCount) / timeSinceLastUpdate
		speedText = fmt.Sprintf("%.0f/s", currentSpeed)
		*lastUpdateTime = now
		*lastCount = currentCount
	} else {
		speedText = "-"
	}

	// Calculate average speed and ETA
	var avgSpeedText, etaText string
	elapsed := time.Since(startTime)
	if currentCount > 0 && elapsed.Seconds() > 0 {
		avgSpeed := float64(currentCount) / elapsed.Seconds()
		avgSpeedText = fmt.Sprintf("%.0f/s", avgSpeed)
		if totalCount > 0 && currentCount < totalCount {
			remaining := totalCount - currentCount
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

	return progressMetrics{
		speedText:    speedText,
		avgSpeedText: avgSpeedText,
		etaText:      etaText,
	}
}

func (bh *BH) loadRemoteComputerResults() map[string]*RemoteCollectionResult {
	remoteFile := filepath.Join(bh.ActiveFolder, "RemoteComputers.msgpack")

	file, err := os.Open(remoteFile)
	if err != nil {
		// File doesn't exist or can't be opened - this is fine, remote collection may not have run
		return nil
	}
	defer file.Close()

	var results map[string]*RemoteCollectionResult
	decoder := msgpack.NewDecoder(file)
	if err := decoder.Decode(&results); err != nil {
		bh.log(" 🫠 [yellow]Warning: Could not decode remote computer results: %s[-]", err.Error())
		return nil
	}

	if len(results) > 0 {
		bh.log("📦 Loaded remote collection data for %s Computers", strconv.Itoa(len(results)))
	}

	return results
}

func (bh *BH) loadRemoteCAResults() map[string]*EnterpriseCARemoteCollectionResult {
	remoteFile := filepath.Join(bh.ActiveFolder, "RemoteEnterpriseCA.msgpack")

	file, err := os.Open(remoteFile)
	if err != nil {
		// File doesn't exist or can't be opened - this is fine, remote collection may not have run
		return nil
	}
	defer file.Close()

	var results map[string]*EnterpriseCARemoteCollectionResult
	decoder := msgpack.NewDecoder(file)
	if err := decoder.Decode(&results); err != nil {
		bh.log("🫠 [yellow]Warning: Could not decode remote CA results:[-] %v", err)
		return nil
	}

	if len(results) > 0 {
		bh.log("📦 Loaded remote collection data for %s Enterprise CAs", strconv.Itoa(len(results)))
	}

	return results
}

func (bh *BH) ProcessObjects(fileNames []string, kind string, step int) int {
	writer, err := bh.GetCurrentWriter(kind)
	if err != nil {
		bh.log("❌ Error getting writer for kind %s: %v", kind, err)
		return 0
	}

	fileName := writer.file.Name()
	defer func() {
		writer.Close()
		// Log file size after writer has been closed and flushed
		if !bh.IsAborted() {
			if fileInfo, err := os.Stat(fileName); err == nil {
				bh.log("✅ [green]Written %s (%s)[-]", fileName, formatFileSize(fileInfo.Size()))
			} else {
				bh.log("🫠 [yellow]Problem saving %s: %v[-]", fileName, err)
			}
		}
	}()

	bh.log("📝 Writing %s to '%s'", kind, fileName)

	totalCount := 0
	totalInFiles := 0

	startTime := time.Now()
	lastUpdateTime := startTime
	lastCount := 0

	readers := make([]*reader.MPReader, 0, len(fileNames))
	for _, fileName := range fileNames {
		reader, err := reader.NewMPReader(fileName)
		if err != nil {
			bh.log("❌ Error opening file %s: %v", fileName, err)
			return 0
		}
		defer reader.Close()

		numEntries, err := reader.ReadLength()
		if err == nil {
			totalInFiles += numEntries
			readers = append(readers, reader)
		}
	}

	if bh.ConversionUpdates != nil {
		bh.ConversionUpdates <- ConversionUpdate{
			Step:      step,
			Processed: 0,
			Total:     totalInFiles,
			Percent:   0.0,
		}
	}

	var wrappedEntry gildap.LDAPEntry
	originalEntry := new(ldap.Entry)

	for _, reader := range readers {
		if bh.IsAborted() {
			return 0
		}

		for i := 0; i < reader.Length(); i++ {
			err := reader.ReadEntry(originalEntry)
			if err != nil {
				bh.log("❌ Error decoding entry: %v", err)
				continue
			}

			wrappedEntry.Init(originalEntry)

			if bh.IsAborted() {
				return 0
			}

			var bhObject interface{}
			var ok bool

			switch kind {
			case "computers":
				bhObject, ok = builder.BuildComputerFromEntry(&wrappedEntry)
				if ok && bh.RuntimeOptions.GetMergeRemote() && bh.RemoteComputerCollection != nil {
					// Enrich object with remote collection results,
					// if present
					computerObject := bhObject.(*builder.Computer)
					if remoteData, found := bh.RemoteComputerCollection[computerObject.ObjectIdentifier]; found {
						remoteData.StoreInComputer(computerObject)
					}
				}
			case "users":
				bhObject, ok = builder.BuildUserFromEntry(&wrappedEntry)
			case "groups":
				bhObject, ok = builder.BuildGroupFromEntry(&wrappedEntry)
			case "ous":
				bhObject, ok = builder.BuildOUFromEntry(&wrappedEntry)
			case "gpos":
				bhObject, ok = builder.BuildGPOFromEntry(&wrappedEntry)
			case "containers":
				if !builder.IsFilteredContainer(wrappedEntry.DN) {
					bhObject, ok = builder.BuildContainerFromEntry(&wrappedEntry)
				} else {
					// TODO: Review
					totalCount++
				}
			default:
				bh.log("❌ Unknown kind: %s", kind)
				continue
			}

			if ok {
				writer.Add(bhObject)
				totalCount++

				if bh.ConversionUpdates != nil {
					elapsed := time.Since(startTime)
					percentage := float64(totalCount) / float64(totalInFiles) * 100.0
					metrics := calculateProgressMetrics(totalCount, totalInFiles, startTime, &lastUpdateTime, &lastCount)

					bh.ConversionUpdates <- ConversionUpdate{
						Step:      step,
						Processed: totalCount,
						Total:     totalInFiles,
						Percent:   percentage,
						Speed:     metrics.speedText,
						AvgSpeed:  metrics.avgSpeedText,
						ETA:       metrics.etaText,
						Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
					}
				}
			}

			if bh.IsAborted() {
				return totalCount
			}
		}

		if bh.IsAborted() {
			return totalCount
		}
	}

	// For each processed domain, add its' well-known objects
	for _, fileName := range fileNames {
		parts := strings.Split(filepath.ToSlash(fileName), "/")
		if len(parts) >= 3 {
			domainName := parts[len(parts)-2]
			bh.addWellKnownObjects(writer, kind, domainName)
		}
	}

	if bh.IsAborted() {
		return totalCount
	}

	if bh.ConversionUpdates != nil {
		bh.ConversionUpdates <- ConversionUpdate{
			Step:      step,
			Processed: totalCount,
			Total:     totalInFiles,
			Percent:   100.0,
		}
	}

	return totalCount
}

// addWellKnownObjects adds well-known built-in groups and users to BloodHound output
func (bh *BH) addWellKnownObjects(writer *BHFormatWriter, kind string, domainName string) {
	if bh.IsAborted() {
		return
	}

	domainSID, ok := builder.BState().DomainSIDCache.Get(domainName)
	if !ok {
		bh.log("🫠 [yellow]Could not find domain SID for domain %s to add well-known %s[-]", domainName, kind)
		domainSID = "UNKNOWN"
	}

	// Only write SEEN well known principals
	if kind == "groups" {
		for sid, wkp := range builder.BState().WellKnown.GetSeen() {
			if bh.IsAborted() {
				return
			}

			if wkp.Type != "Group" {
				continue
			}

			object := builder.BuildWellKnownGroup(sid, wkp.Name, domainName, domainSID)
			writer.Add(object)
		}
	} else if kind == "users" {
		for sid, wkp := range builder.BState().WellKnown.GetSeen() {
			if bh.IsAborted() {
				return
			}

			if wkp.Type != "User" {
				continue
			}

			object := builder.BuildWellKnownUser(sid, wkp.Name, domainName, domainSID)
			writer.Add(object)
		}
	}
}

// ProcessDomain reads domain entries and creates a domain JSON file
func (bh *BH) ProcessDomain(step int) {
	if bh.IsAborted() {
		return
	}

	domainWriter, err := bh.GetCurrentWriter("domains")
	if err != nil {
		bh.log("❌ Error getting writer for domains: %v", err)
		return
	}
	fileName := domainWriter.file.Name()
	defer func() {
		domainWriter.Close()
		// Log file size after writer has been closed and flushed
		if !bh.IsAborted() {
			if fileInfo, err := os.Stat(fileName); err == nil {
				bh.log("✅ [green]Written %s (%s)[-]", fileName, formatFileSize(fileInfo.Size()))
			} else {
				bh.log("🫠 [yellow]Problem saving %s: %v[-]", fileName, err)
			}
		}
	}()

	domainEntries, _ := os.ReadDir(bh.LdapFolder)

	// Calculate total entries across all domain directories
	totalInFiles := 0
	startTime := time.Now()
	lastUpdateTime := startTime
	lastCount := 0

	type domainReaderInfo struct {
		domainName string
		reader     *reader.MPReader
		trusts     []gildap.LDAPEntry
	}
	domainReaders := make([]domainReaderInfo, 0)

	for _, domainEntry := range domainEntries {
		if !domainEntry.IsDir() || strings.HasPrefix(domainEntry.Name(), "FOREST+") {
			continue
		}

		domainPath := filepath.Join(bh.LdapFolder, domainEntry.Name(), "Domains.msgpack")
		trustsPath := filepath.Join(bh.LdapFolder, domainEntry.Name(), "Trusts.msgpack")

		trusts := bh.loadTrusts(trustsPath)

		domainsReader, err := reader.NewMPReader(domainPath)
		if err != nil {
			bh.log("❌ Error opening domains file: %v", err)
			continue
		}
		defer domainsReader.Close()

		totalInFile, err := domainsReader.ReadLength()
		if err != nil {
			bh.log("❌ Error reading length of domains file: %v", err)
			continue
		}

		totalInFiles += totalInFile
		domainReaders = append(domainReaders, domainReaderInfo{
			domainName: domainEntry.Name(),
			reader:     domainsReader,
			trusts:     trusts,
		})
	}

	processedCount := 0
	originalEntry := new(ldap.Entry)
	var entry gildap.LDAPEntry

	if bh.ConversionUpdates != nil {
		bh.ConversionUpdates <- ConversionUpdate{
			Step:      step,
			Processed: 0,
			Total:     totalInFiles,
			Percent:   0.0,
		}
	}

	for _, info := range domainReaders {
		for i := 0; i < info.reader.Length(); i++ {
			if bh.IsAborted() {
				return
			}

			*originalEntry = ldap.Entry{}
			if err := info.reader.ReadEntry(originalEntry); err != nil {
				bh.log("❌ Error decoding domain: %v", err)
				continue
			}

			entry.Init(originalEntry)

			domain := builder.BuildDomainFromEntry(&entry, info.trusts)
			domainWriter.Add(domain)

			processedCount++
			if bh.ConversionUpdates != nil {
				elapsed := time.Since(startTime)
				percentage := float64(processedCount) / float64(totalInFiles) * 100.0
				metrics := calculateProgressMetrics(processedCount, totalInFiles, startTime, &lastUpdateTime, &lastCount)

				bh.ConversionUpdates <- ConversionUpdate{
					Step:      step,
					Processed: processedCount,
					Total:     totalInFiles,
					Percent:   percentage,
					Speed:     metrics.speedText,
					AvgSpeed:  metrics.avgSpeedText,
					ETA:       metrics.etaText,
					Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
				}
			}
		}

		if bh.IsAborted() {
			return
		}
	}
}

// loadTrusts reads trust entries from the trusts file
func (bh *BH) loadTrusts(trustsPath string) []gildap.LDAPEntry {
	var trusts []gildap.LDAPEntry

	mpReader, err := reader.NewMPReader(trustsPath)
	if err != nil {
		bh.log("❌ Error opening trusts file: %v", err)
		return trusts
	}
	defer mpReader.Close()

	_, err = mpReader.ReadLength()
	if err != nil {
		bh.log("❌ Error reading length of trusts file: %v", err)
		return trusts
	}

	originalEntry := new(ldap.Entry)
	var entry gildap.LDAPEntry

	for i := 0; i < mpReader.Length(); i++ {
		if bh.IsAborted() {
			return trusts
		}

		*originalEntry = ldap.Entry{}
		if err := mpReader.ReadEntry(originalEntry); err != nil {
			bh.log("❌ Error decoding trust: %v", err)
			continue
		}

		entry.Init(originalEntry)
		trusts = append(trusts, entry)
	}

	return trusts
}

// ProcessConfiguration processes configuration entries for PKI objects
func (bh *BH) ProcessConfiguration(step int) {
	if bh.IsAborted() {
		return
	}

	// Initialize all writers
	ctWriter, _ := bh.GetCurrentWriter("certtemplates")
	ctFileName := ctWriter.file.Name()
	defer func() {
		ctWriter.Close()
		if !bh.IsAborted() {
			if fileInfo, err := os.Stat(ctFileName); err == nil {
				bh.log("✅ [green]Written %s (%s)[-]", ctFileName, formatFileSize(fileInfo.Size()))
			}
		}
	}()

	enterpriseCAWriter, _ := bh.GetCurrentWriter("enterprisecas")
	enterpriseCAFileName := enterpriseCAWriter.file.Name()
	defer func() {
		enterpriseCAWriter.Close()
		if !bh.IsAborted() {
			if fileInfo, err := os.Stat(enterpriseCAFileName); err == nil {
				bh.log("✅ [green]Written %s (%s)[-]", enterpriseCAFileName, formatFileSize(fileInfo.Size()))
			}
		}
	}()

	aiacaWriter, _ := bh.GetCurrentWriter("aiacas")
	aiacaFileName := aiacaWriter.file.Name()
	defer func() {
		aiacaWriter.Close()
		if !bh.IsAborted() {
			if fileInfo, err := os.Stat(aiacaFileName); err == nil {
				bh.log("✅ [green]Written %s (%s)[-]", aiacaFileName, formatFileSize(fileInfo.Size()))
			}
		}
	}()

	rootCAWriter, _ := bh.GetCurrentWriter("rootcas")
	rootCAFileName := rootCAWriter.file.Name()
	defer func() {
		rootCAWriter.Close()
		if !bh.IsAborted() {
			if fileInfo, err := os.Stat(rootCAFileName); err == nil {
				bh.log("✅ [green]Written %s (%s)[-]", rootCAFileName, formatFileSize(fileInfo.Size()))
			}
		}
	}()

	ntAuthStoresWriter, _ := bh.GetCurrentWriter("ntauthstores")
	ntAuthStoresFileName := ntAuthStoresWriter.file.Name()
	defer func() {
		ntAuthStoresWriter.Close()
		if !bh.IsAborted() {
			if fileInfo, err := os.Stat(ntAuthStoresFileName); err == nil {
				bh.log("✅ [green]Written %s (%s)[-]", ntAuthStoresFileName, formatFileSize(fileInfo.Size()))
			}
		}
	}()

	issuancePoliciesWriter, _ := bh.GetCurrentWriter("issuancepolicies")
	issuancePoliciesFileName := issuancePoliciesWriter.file.Name()
	defer func() {
		issuancePoliciesWriter.Close()
		if !bh.IsAborted() {
			if fileInfo, err := os.Stat(issuancePoliciesFileName); err == nil {
				bh.log("✅ [green]Written %s (%s)[-]", issuancePoliciesFileName, formatFileSize(fileInfo.Size()))
			}
		}
	}()

	bh.GetCurrentWriter("containers")
	// We shouldn't close this one and it's used for later steps

	configPaths, _ := bh.GetPaths("configuration")

	// Calculate total entries across all files
	totalInFiles := 0
	startTime := time.Now()
	lastUpdateTime := startTime
	lastCount := 0

	readers := make([]*reader.MPReader, 0, len(configPaths))
	for _, configPath := range configPaths {
		mpReader, err := reader.NewMPReader(configPath)
		if err != nil {
			bh.log("❌ Error opening configuration file: %v", err)
			continue
		}
		defer mpReader.Close()

		totalInFile, err := mpReader.ReadLength()
		if err != nil {
			bh.log("❌ Error reading length of configuration file: %v", err)
			continue
		}
		totalInFiles += totalInFile
		readers = append(readers, mpReader)
	}

	processedCount := 0

	originalEntry := new(ldap.Entry)
	var entry gildap.LDAPEntry

	if bh.ConversionUpdates != nil {
		bh.ConversionUpdates <- ConversionUpdate{
			Step:      step,
			Processed: 0,
			Total:     totalInFiles,
			Percent:   0.0,
		}
	}

	for _, mpReader := range readers {
		for i := 0; i < mpReader.Length(); i++ {
			if bh.IsAborted() {
				return
			}

			*originalEntry = ldap.Entry{}
			if err := mpReader.ReadEntry(originalEntry); err != nil {
				bh.log("❌ Error decoding configuration entry: %v", err)
				continue
			}

			entry.Init(originalEntry)

			bh.processConfigurationEntry(&entry)

			processedCount++

			if bh.ConversionUpdates != nil {
				elapsed := time.Since(startTime)
				percentage := float64(processedCount) / float64(totalInFiles) * 100.0
				metrics := calculateProgressMetrics(processedCount, totalInFiles, startTime, &lastUpdateTime, &lastCount)

				bh.ConversionUpdates <- ConversionUpdate{
					Step:      step,
					Processed: processedCount,
					Total:     totalInFiles,
					Percent:   percentage,
					Speed:     metrics.speedText,
					AvgSpeed:  metrics.avgSpeedText,
					ETA:       metrics.etaText,
					Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
				}
			}
		}

		if bh.IsAborted() {
			return
		}
	}

	if bh.ConversionUpdates != nil {
		bh.ConversionUpdates <- ConversionUpdate{
			Step:      step,
			Processed: processedCount,
			Total:     totalInFiles,
			Percent:   100.0,
		}
	}
}

// processConfigurationEntry processes a single configuration entry
func (bh *BH) processConfigurationEntry(entry *gildap.LDAPEntry) {
	if bh.IsAborted() {
		return
	}

	objectClasses := entry.GetAttrVals("objectClass", []string{})

	if slices.Contains(objectClasses, "pKICertificateTemplate") {
		certTemplate, ok := builder.BuildCertTemplateFromEntry(entry)
		if ok {
			if writer, _ := bh.GetCurrentWriter("certtemplates"); writer != nil {
				writer.Add(certTemplate)
			}
		}
	} else if slices.Contains(objectClasses, "pKIEnrollmentService") {
		enterpriseCA, ok := builder.BuildEnterpriseCAFromEntry(entry)
		if ok {
			// Enrich object with remote collection results,
			// if present
			if bh.RuntimeOptions.GetMergeRemote() && bh.RemoteEnterpriseCACollection != nil {
				if remoteData, found := bh.RemoteEnterpriseCACollection[enterpriseCA.ObjectIdentifier]; found {
					mergeRemoteEnterpriseCACollection(enterpriseCA, remoteData)
				}
			}
			if writer, _ := bh.GetCurrentWriter("enterprisecas"); writer != nil {
				writer.Add(enterpriseCA)
			}
		}
	} else if slices.Contains(objectClasses, "certificationAuthority") {
		bh.processCertificationAuthority(entry)
	} else if strings.HasPrefix(entry.DN, directoryPaths["OIDContainerLocation"]) {
		container, ok := builder.BuildContainerFromEntry(entry)
		if ok {
			if writer, _ := bh.GetCurrentWriter("containers"); writer != nil {
				writer.Add(container)
			}
		}
	} else if slices.Contains(objectClasses, "msPKI-Enterprise-Oid") {
		flags := entry.GetAttrVal("flags", "0")
		if flags == "2" {
			issuancePolicy, ok := builder.BuildIssuancePolicyFromEntry(entry)
			if ok {
				if writer, _ := bh.GetCurrentWriter("issuancepolicies"); writer != nil {
					writer.Add(issuancePolicy)
				}
			}
		}
	} else if slices.Contains(objectClasses, "configuration") || slices.Contains(objectClasses, "container") {
		container, ok := builder.BuildContainerFromEntry(entry)
		if ok {
			if writer, _ := bh.GetCurrentWriter("containers"); writer != nil {
				writer.Add(container)
			}
		}
	}
}

// processCertificationAuthority processes a Certification Authority entry
func (bh *BH) processCertificationAuthority(entry *gildap.LDAPEntry) {
	if bh.IsAborted() {
		return
	}

	if strings.Contains(entry.DN, directoryPaths["RootCALocation"]) {
		rootCA, ok := builder.BuildRootCAFromEntry(entry)
		if ok {
			if writer, _ := bh.GetCurrentWriter("rootcas"); writer != nil {
				writer.Add(rootCA)
			}
		}
	} else if strings.Contains(entry.DN, directoryPaths["AIACALocation"]) {
		aiaCA, ok := builder.BuildAIACAFromEntry(entry)
		if ok {
			if writer, _ := bh.GetCurrentWriter("aiacas"); writer != nil {
				writer.Add(aiaCA)
			}
		}
	} else if strings.Contains(entry.DN, directoryPaths["NTAuthStoreLocation"]) {
		ntAuthStore, ok := builder.BuildNTAuthStoreFromEntry(entry)
		if ok {
			if writer, _ := bh.GetCurrentWriter("ntauthstores"); writer != nil {
				writer.Add(ntAuthStore)
			}
		}
	}
}

// LoadSchemaInfo loads schema information from the schema file
func (bh *BH) LoadSchemaInfo(step int) {
	if bh.IsAborted() {
		return
	}

	schemaPaths, _ := bh.GetPaths("schema")

	// Calculate total entries across all files
	totalInFiles := 0
	startTime := time.Now()
	lastUpdateTime := startTime
	lastCount := 0

	readers := make([]*reader.MPReader, 0, len(schemaPaths))
	for _, schemaPath := range schemaPaths {
		mpReader, err := reader.NewMPReader(schemaPath)
		if err != nil {
			bh.log("❌ Error opening schema file: %v", err)
			continue
		}
		defer mpReader.Close()

		totalInFile, err := mpReader.ReadLength()
		if err != nil {
			bh.log("❌ Error reading length of schema file: %v", err)
			continue
		}
		totalInFiles += totalInFile
		readers = append(readers, mpReader)
	}

	processedCount := 0
	originalEntry := new(ldap.Entry)
	var entry gildap.LDAPEntry

	if bh.ConversionUpdates != nil {
		bh.ConversionUpdates <- ConversionUpdate{
			Step:      step,
			Processed: 0,
			Total:     totalInFiles,
			Percent:   0.0,
		}
	}

	for _, mpReader := range readers {
		for i := 0; i < mpReader.Length(); i++ {
			if bh.IsAborted() {
				return
			}

			*originalEntry = ldap.Entry{}
			if err := mpReader.ReadEntry(originalEntry); err != nil {
				bh.log("❌ Error decoding schema entry: %v", err)
				continue
			}

			entry.Init(originalEntry)

			name := entry.GetAttrVal("name", "")
			schemaIDGUID := entry.GetAttrRawVal("schemaIDGUID", []byte{})
			guidStr := gildap.BytesToGUID(schemaIDGUID)

			domainName := entry.GetDomainFromDN()
			forestName := builder.BState().GetForestRoot(domainName)

			builder.BState().AttrGUIDMap.Store(
				forestName+"+"+strings.ToLower(name),
				guidStr,
			)

			processedCount++

			if bh.ConversionUpdates != nil {
				elapsed := time.Since(startTime)
				percentage := float64(processedCount) / float64(totalInFiles) * 100.0
				metrics := calculateProgressMetrics(processedCount, totalInFiles, startTime, &lastUpdateTime, &lastCount)

				bh.ConversionUpdates <- ConversionUpdate{
					Step:      step,
					Processed: processedCount,
					Total:     totalInFiles,
					Percent:   percentage,
					Speed:     metrics.speedText,
					AvgSpeed:  metrics.avgSpeedText,
					ETA:       metrics.etaText,
					Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
				}
			}
		}
	}
}

// PerformConversion transforms LDAP data to BloodHound JSON format with progress tracking.
const TotalConversionSteps = 11

func (bh *BH) PerformConversion() {
	// Update timestamp for this conversion run
	bh.Timestamp = time.Now().Format("20060102150405")
	bh.generatedFiles = make([]string, 0)

	abortLogged := false
	notifyAbort := func(currentStep int) bool {
		if bh.IsAborted() {
			if !abortLogged && bh.Log != nil {
				bh.log("🛑 Conversion abort requested. Stopping remaining steps...")
				abortLogged = true
			}
			// Mark remaining steps as skipped
			for step := currentStep + 1; step <= TotalConversionSteps; step++ {
				if bh.ConversionUpdates != nil {
					bh.ConversionUpdates <- ConversionUpdate{
						Step:   step,
						Status: "skipped",
					}
				}
			}
			return true
		}
		return false
	}

	if notifyAbort(0) {
		return
	}

	// Initialize builder state
	forestMapPath := filepath.Join(bh.LdapFolder, "ForestDomains.json")
	builder.BState().Init(forestMapPath)

	if notifyAbort(0) {
		return
	}

	// Load remote collection results if available
	bh.RemoteComputerCollection = bh.loadRemoteComputerResults()
	bh.RemoteEnterpriseCACollection = bh.loadRemoteCAResults()

	// Load cache and schema (rows 1-2)
	bh.runConversionStep(1, func() { bh.loadConversionCache(1) })
	if notifyAbort(1) {
		return
	}
	bh.runConversionStep(2, func() { bh.LoadSchemaInfo(2) })
	if notifyAbort(2) {
		return
	}

	// Process domains and configuration (rows 3-4)
	bh.runConversionStep(3, func() { bh.ProcessDomain(3) })
	if notifyAbort(3) {
		return
	}

	bh.runConversionStep(4, func() { bh.ProcessConfiguration(4) })
	if notifyAbort(4) {
		return
	}

	// Process all object types (rows 5-10)
	gposPaths, _ := bh.GetPaths("gpos")
	bh.runConversionStep(5, func() { bh.ProcessObjects(gposPaths, "gpos", 5) })
	if notifyAbort(5) {
		return
	}

	ousPaths, _ := bh.GetPaths("ous")
	bh.runConversionStep(6, func() { bh.ProcessObjects(ousPaths, "ous", 6) })
	if notifyAbort(6) {
		return
	}

	containersPaths, _ := bh.GetPaths("containers")
	bh.runConversionStep(7, func() { bh.ProcessObjects(containersPaths, "containers", 7) })
	if notifyAbort(7) {
		return
	}

	groupsPaths, _ := bh.GetPaths("groups")
	bh.runConversionStep(8, func() { bh.ProcessObjects(groupsPaths, "groups", 8) })
	if notifyAbort(8) {
		return
	}

	computersPaths, _ := bh.GetPaths("computers")
	bh.runConversionStep(9, func() { bh.ProcessObjects(computersPaths, "computers", 9) })
	if notifyAbort(9) {
		return
	}

	usersPaths, _ := bh.GetPaths("users")
	bh.runConversionStep(10, func() { bh.ProcessObjects(usersPaths, "users", 10) })
	if notifyAbort(10) {
		return
	}

	// Compress output if enabled (row 11)
	if bh.RuntimeOptions.GetCompressOutput() {
		bh.runConversionStep(11, func() { bh.compressBloodhoundOutput(11) })
	}

	if builder.BState().EmptySDCount > 0 {
		bh.log("🫠 [yellow]Security descriptors were not present in %d entries. Permissions issue during ingestion?[-]", builder.BState().EmptySDCount)
	}
}

// runConversionStep runs a conversion step and sends progress events
func (bh *BH) runConversionStep(row int, stepFunc func()) {
	if bh.IsAborted() {
		return
	}

	if bh.ConversionUpdates != nil {
		bh.ConversionUpdates <- ConversionUpdate{
			Step:   row,
			Status: "running",
		}
	}

	startTime := time.Now()
	stepFunc()
	elapsed := time.Since(startTime)

	if bh.IsAborted() {
		if bh.ConversionUpdates != nil {
			bh.ConversionUpdates <- ConversionUpdate{
				Step:    row,
				Status:  "aborted",
				Elapsed: elapsed.Round(10 * time.Millisecond).String(),
			}
		}
		return
	}

	if bh.ConversionUpdates != nil {
		bh.ConversionUpdates <- ConversionUpdate{
			Step:    row,
			Status:  "done",
			Elapsed: elapsed.Round(10 * time.Millisecond).String(),
		}
	}
}

// loadConversionCache loads all necessary caches for conversion
func (bh *BH) loadConversionCache(step int) {
	if bh.IsAborted() {
		return
	}

	startTime := time.Now()
	lastUpdateTime := startTime
	var lastCount int
	totalProcessed := 0
	totalEntries := 0

	neededCaches := []string{
		"domains", "users", "groups", "computers",
		"configuration", "trusts", "gpos", "ous", "containers",
	}

	// First pass: open all readers and read their lengths
	type readerInfo struct {
		reader     *reader.MPReader
		identifier string
	}
	readers := make([]readerInfo, 0)

	for _, cache := range neededCaches {
		filePaths, _ := bh.GetPaths(cache)
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
				identifier: cache,
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
		var speedText string
		var avgSpeedText string
		var etaText string

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

		if bh.ConversionUpdates != nil {
			percentage := 0.0
			if totalEntries > 0 {
				percentage = float64(totalProcessed) / float64(totalEntries) * 100.0
			}

			bh.ConversionUpdates <- ConversionUpdate{
				Step:      step,
				Processed: totalProcessed,
				Total:     totalEntries,
				Percent:   percentage,
				Speed:     speedText,
				AvgSpeed:  avgSpeedText,
				ETA:       etaText,
				Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
			}
		}
	}

	// Second pass: process all readers sequentially
	for _, info := range readers {
		if bh.IsAborted() {
			return
		}

		filePath := info.reader.GetPath()
		bh.logVerbose("📦 Loading %s", filePath)

		builder.BState().CacheEntries(info.reader, info.identifier, bh.Log, bh.IsAborted, progressCallback)

		// Mark this cache as loaded
		builder.BState().MarkCacheLoaded(filePath)

		bh.logVerbose("✅ %s loaded", filePath)
	}
}

// compressBloodhoundOutput packages all generated BloodHound JSON files into a timestamped zip archive
func (bh *BH) compressBloodhoundOutput(step int) {
	if bh.IsAborted() {
		return
	}

	// Filter to only include files that were successfully generated and exist
	var filesToCompress []string
	for _, file := range bh.generatedFiles {
		if _, err := os.Stat(file); err == nil {
			filesToCompress = append(filesToCompress, file)
		}
	}

	if len(filesToCompress) == 0 {
		bh.log("🫠 [yellow]No JSON files found to compress[-]")
		return
	}

	// Create zip file using the current timestamp
	zipPath := filepath.Join(bh.OutputFolder, bh.Timestamp+"_BloodHound.zip")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		bh.log("❌ Error creating zip file: %v", err)
		return
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Initialize progress tracking
	startTime := time.Now()
	lastUpdateTime := startTime
	var lastCount int
	totalFiles := len(filesToCompress)

	// Send initial update
	if bh.ConversionUpdates != nil {
		bh.ConversionUpdates <- ConversionUpdate{
			Step:      step,
			Processed: 0,
			Total:     totalFiles,
			Percent:   0.0,
		}
	}

	// Add each JSON file to the zip
	for i, file := range filesToCompress {
		if bh.IsAborted() {
			return
		}

		if err := bh.addFileToZip(zipWriter, file); err != nil {
			bh.log("❌ Error adding file to zip: %v", err)
			return
		}

		// Update progress
		count := i + 1
		if bh.ConversionUpdates != nil {
			elapsed := time.Since(startTime)
			percentage := float64(count) / float64(totalFiles) * 100.0
			metrics := calculateProgressMetrics(count, totalFiles, startTime, &lastUpdateTime, &lastCount)

			bh.ConversionUpdates <- ConversionUpdate{
				Step:      step,
				Processed: count,
				Total:     totalFiles,
				Percent:   percentage,
				Speed:     metrics.speedText,
				AvgSpeed:  metrics.avgSpeedText,
				ETA:       metrics.etaText,
				Elapsed:   elapsed.Round(10 * time.Millisecond).String(),
			}
		}
	}

	// Close the zip writer before getting file size
	if err := zipWriter.Close(); err != nil {
		bh.log("❌ Error finalizing zip: %v", err)
		return
	}

	// Get zip file size
	if fileInfo, err := os.Stat(zipPath); err == nil {
		bh.log("✅ [green]BloodHound dump: \"%s\" (%s)[-]", zipPath, formatFileSize(fileInfo.Size()))
	} else {
		bh.log("🫠 [yellow]Problem saving \"%s\": %v[-]", zipPath, err)
	}

	// Cleanup original files if enabled
	if bh.RuntimeOptions.GetCleanupAfterCompression() {
		for _, file := range filesToCompress {
			if err := os.Remove(file); err != nil {
				bh.log("🫠 [yellow]Could not remove \"%s\":[-] %v", filepath.Base(file), err)
			}
		}
		bh.log("🧹 Cleaned up %d original JSON files from \"%s\"", len(filesToCompress), bh.OutputFolder)
	}
}

// addFileToZip adds a single file to the zip archive
func (bh *BH) addFileToZip(zipWriter *zip.Writer, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create zip entry with just the filename (not full path)
	basename := filepath.Base(filePath)
	writer, err := zipWriter.Create(basename)
	if err != nil {
		return err
	}

	// Copy file contents to zip
	_, err = io.Copy(writer, file)
	return err
}
