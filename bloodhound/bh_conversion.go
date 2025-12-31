package bloodhound

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	//"sync"
	"time"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	gildap "github.com/Macmod/flashingestor/ldap"
	"github.com/Macmod/flashingestor/reader"
	"github.com/Macmod/flashingestor/ui"
	"github.com/go-ldap/ldap/v3"
	"github.com/vmihailenco/msgpack"
)

// ConversionProgressTracker manages real-time progress updates during conversion.
type ConversionProgressTracker struct {
	startTime      time.Time
	lastUpdateTime time.Time
	lastCount      int
	row            int
	uiApp          *ui.Application
	isAborted      func() bool
	stopped        bool
}

func newConversionProgressTracker(row int, uiApp *ui.Application, isAborted func() bool) *ConversionProgressTracker {
	now := time.Now()
	return &ConversionProgressTracker{
		startTime:      now,
		lastUpdateTime: now,
		lastCount:      0,
		row:            row,
		uiApp:          uiApp,
		isAborted:      isAborted,
	}
}

// createProgressCallback creates a progress callback function for UI updates
func (t *ConversionProgressTracker) createProgressCallback() func(int, int) {
	return func(count, total int) {
		if t.stopped || t.isAborted() || t.uiApp == nil {
			return
		}

		elapsed := time.Since(t.startTime)
		progressText := t.formatProgress(count, total)
		percentText := t.formatPercentage(count, total)
		speedText := t.calculateCurrentSpeed(count)
		avgSpeedText, etaText := t.calculateAvgSpeedAndETA(count, total, elapsed)

		t.uiApp.UpdateConversionRow(t.row, "", progressText, percentText, speedText, avgSpeedText, etaText, elapsed.Round(time.Second).String())
	}
}

// formatProgress formats the progress text with color coding
func (t *ConversionProgressTracker) formatProgress(count, total int) string {
	if total > 0 {
		if count == total {
			return fmt.Sprintf("[green]%d/%d[-]", count, total)
		}
		return fmt.Sprintf("[blue]%d/%d[-]", count, total)
	}
	return strconv.Itoa(count)
}

// formatPercentage formats the percentage text with color coding
func (t *ConversionProgressTracker) formatPercentage(count, total int) string {
	if total > 0 {
		percentage := float64(count) / float64(total) * 100.0
		if percentage >= 100.0 {
			return fmt.Sprintf("[green]%.1f%%[-]", percentage)
		}
		return fmt.Sprintf("[blue]%.1f%%[-]", percentage)
	}
	return "-"
}

// calculateCurrentSpeed calculates the current processing speed
func (t *ConversionProgressTracker) calculateCurrentSpeed(count int) string {
	now := time.Now()
	timeSinceLastUpdate := now.Sub(t.lastUpdateTime).Seconds()
	if timeSinceLastUpdate > 0 && count > t.lastCount {
		currentSpeed := float64(count-t.lastCount) / timeSinceLastUpdate
		t.lastUpdateTime = now
		t.lastCount = count
		return fmt.Sprintf("%.0f/s", currentSpeed)
	}
	return "-"
}

// calculateAvgSpeedAndETA calculates average speed and estimated time of arrival
func (t *ConversionProgressTracker) calculateAvgSpeedAndETA(count, total int, elapsed time.Duration) (string, string) {
	if count > 0 && elapsed.Seconds() > 0 {
		avgSpeed := float64(count) / elapsed.Seconds()
		avgSpeedText := fmt.Sprintf("%.0f/s", avgSpeed)

		var etaText string
		if total > 0 && count < total {
			remaining := total - count
			etaSeconds := float64(remaining) / avgSpeed
			etaDuration := time.Duration(etaSeconds * float64(time.Second))
			etaText = etaDuration.Round(time.Second).String()
		} else {
			etaText = "-"
		}
		return avgSpeedText, etaText
	}
	return "-", "-"
}

// stop prevents any further progress updates from this tracker
func (t *ConversionProgressTracker) stop() {
	t.stopped = true
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
		bh.Log <- " [yellow]Warning: Could not decode remote computer results: " + err.Error() + "[-]"
		return nil
	}

	if len(results) > 0 {
		bh.Log <- "📦 Loaded remote collection data for " + strconv.Itoa(len(results)) + " Computers"
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
		bh.Log <- "[yellow]⚠ Warning: Could not decode remote CA results:[-] " + err.Error()
		return nil
	}

	if len(results) > 0 {
		bh.Log <- "📦 Loaded remote collection data for " + strconv.Itoa(len(results)) + " Enterprise CAs"
	}

	return results
}

func (bh *BH) ProcessObjects(fileNames []string, kind string, progressCallback func(count, total int)) int {
	writer, err := bh.GetCurrentWriter(kind)
	if err != nil {
		bh.Log <- "❌ Error getting writer for kind " + kind + ": " + err.Error()
		return 0
	}

	fileName := writer.file.Name()
	defer func() {
		writer.Close()
		// Log file size after writer has been closed and flushed
		if !bh.IsAborted() {
			if fileInfo, err := os.Stat(fileName); err == nil {
				bh.Log <- fmt.Sprintf("✅ [green]Written %s (%s)[-]", fileName, formatFileSize(fileInfo.Size()))
			} else {
				bh.Log <- fmt.Sprintf("🫠 [yellow]Problem saving %s: %v[-]", fileName, err)
			}
		}
	}()

	bh.Log <- "📝 Writing " + kind + " to '" + fileName + "'"

	totalCount := 0
	batchCount := 0
	totalInFiles := 0
	const progressInterval = 10

	readers := make([]*reader.MPReader, 0, len(fileNames))
	for _, fileName := range fileNames {
		reader, err := reader.NewMPReader(fileName)
		if err != nil {
			bh.Log <- "❌ Error opening file " + fileName + ": " + err.Error()
			return 0
		}
		defer reader.Close()

		numEntries, err := reader.ReadLength()
		if err == nil {
			totalInFiles += numEntries
			readers = append(readers, reader)
		}
	}

	progressCallback(0, totalInFiles)

	var wrappedEntry gildap.LDAPEntry
	originalEntry := new(ldap.Entry)

	for _, reader := range readers {
		if bh.IsAborted() {
			return 0
		}

		for i := 0; i < reader.Length(); i++ {
			err := reader.ReadEntry(originalEntry)
			if err != nil {
				bh.Log <- "❌ Error decoding entry: " + err.Error()
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
				bh.Log <- "❌ Unknown kind: " + kind
				continue
			}

			if ok {
				writer.Add(bhObject)
				totalCount++
				batchCount++

				if batchCount >= progressInterval {
					if progressCallback != nil {
						progressCallback(totalCount, totalInFiles)
					}
					batchCount = 0
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

	if progressCallback != nil {
		progressCallback(totalCount, totalInFiles)
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
		bh.Log <- "[yellow]🫠 Could not find domain SID for domain " + domainName + " to add well-known " + kind + "[-]"
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
func (bh *BH) ProcessDomain(progressCallback func(count, total int)) {
	if bh.IsAborted() {
		return
	}

	domainWriter, err := bh.GetCurrentWriter("domains")
	if err != nil {
		bh.Log <- "❌ Error getting writer for domains: " + err.Error()
		return
	}
	fileName := domainWriter.file.Name()
	defer func() {
		domainWriter.Close()
		// Log file size after writer has been closed and flushed
		if !bh.IsAborted() {
			if fileInfo, err := os.Stat(fileName); err == nil {
				bh.Log <- fmt.Sprintf("✅ [green]Written %s (%s)[-]", fileName, formatFileSize(fileInfo.Size()))
			} else {
				bh.Log <- fmt.Sprintf("🫠 [yellow]Problem saving %s: %v[-]", fileName, err)
			}
		}
	}()

	domainEntries, _ := os.ReadDir(bh.LdapFolder)

	for _, domainEntry := range domainEntries {
		if !domainEntry.IsDir() {
			continue
		}

		domainPath := filepath.Join(bh.LdapFolder, domainEntry.Name(), "Domains.msgpack")
		trustsPath := filepath.Join(bh.LdapFolder, domainEntry.Name(), "Trusts.msgpack")

		trusts := bh.loadTrusts(trustsPath)

		domainsReader, err := reader.NewMPReader(domainPath)
		if err != nil {
			bh.Log <- "❌ Error opening domains file: " + err.Error()
			continue
		}
		defer domainsReader.Close()

		totalInFile, err := domainsReader.ReadLength()
		if err != nil {
			bh.Log <- "❌ Error reading length of domains file: " + err.Error()
			continue
		}

		processedCount := 0

		originalEntry := new(ldap.Entry)
		var entry gildap.LDAPEntry

		if progressCallback != nil {
			progressCallback(0, totalInFile)
		}

		for i := 0; i < domainsReader.Length(); i++ {
			if bh.IsAborted() {
				return
			}

			*originalEntry = ldap.Entry{}
			if err := domainsReader.ReadEntry(originalEntry); err != nil {
				bh.Log <- "❌ Error decoding domain: " + err.Error()
				continue
			}

			entry.Init(originalEntry)

			domain := builder.BuildDomainFromEntry(&entry, trusts)
			domainWriter.Add(domain)

			processedCount++
			if progressCallback != nil {
				progressCallback(processedCount, totalInFile)
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
		bh.Log <- "❌ Error opening trusts file: " + err.Error()
		return trusts
	}
	defer mpReader.Close()

	_, err = mpReader.ReadLength()
	if err != nil {
		bh.Log <- "❌ Error reading length of trusts file: " + err.Error()
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
			bh.Log <- "❌ Error decoding trust: " + err.Error()
			continue
		}

		entry.Init(originalEntry)
		trusts = append(trusts, entry)
	}

	return trusts
}

// ProcessConfiguration processes configuration entries for PKI objects
func (bh *BH) ProcessConfiguration(progressCallback func(count, total int)) {
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
				bh.Log <- fmt.Sprintf("✅ [green]Written %s (%s)[-]", ctFileName, formatFileSize(fileInfo.Size()))
			}
		}
	}()

	enterpriseCAWriter, _ := bh.GetCurrentWriter("enterprisecas")
	enterpriseCAFileName := enterpriseCAWriter.file.Name()
	defer func() {
		enterpriseCAWriter.Close()
		if !bh.IsAborted() {
			if fileInfo, err := os.Stat(enterpriseCAFileName); err == nil {
				bh.Log <- fmt.Sprintf("✅ [green]Written %s (%s)[-]", enterpriseCAFileName, formatFileSize(fileInfo.Size()))
			}
		}
	}()

	aiacaWriter, _ := bh.GetCurrentWriter("aiacas")
	aiacaFileName := aiacaWriter.file.Name()
	defer func() {
		aiacaWriter.Close()
		if !bh.IsAborted() {
			if fileInfo, err := os.Stat(aiacaFileName); err == nil {
				bh.Log <- fmt.Sprintf("✅ [green]Written %s (%s)[-]", aiacaFileName, formatFileSize(fileInfo.Size()))
			}
		}
	}()

	rootCAWriter, _ := bh.GetCurrentWriter("rootcas")
	rootCAFileName := rootCAWriter.file.Name()
	defer func() {
		rootCAWriter.Close()
		if !bh.IsAborted() {
			if fileInfo, err := os.Stat(rootCAFileName); err == nil {
				bh.Log <- fmt.Sprintf("✅ [green]Written %s (%s)[-]", rootCAFileName, formatFileSize(fileInfo.Size()))
			}
		}
	}()

	ntAuthStoresWriter, _ := bh.GetCurrentWriter("ntauthstores")
	ntAuthStoresFileName := ntAuthStoresWriter.file.Name()
	defer func() {
		ntAuthStoresWriter.Close()
		if !bh.IsAborted() {
			if fileInfo, err := os.Stat(ntAuthStoresFileName); err == nil {
				bh.Log <- fmt.Sprintf("✅ [green]Written %s (%s)[-]", ntAuthStoresFileName, formatFileSize(fileInfo.Size()))
			}
		}
	}()

	issuancePoliciesWriter, _ := bh.GetCurrentWriter("issuancepolicies")
	issuancePoliciesFileName := issuancePoliciesWriter.file.Name()
	defer func() {
		issuancePoliciesWriter.Close()
		if !bh.IsAborted() {
			if fileInfo, err := os.Stat(issuancePoliciesFileName); err == nil {
				bh.Log <- fmt.Sprintf("✅ [green]Written %s (%s)[-]", issuancePoliciesFileName, formatFileSize(fileInfo.Size()))
			}
		}
	}()

	bh.GetCurrentWriter("containers")
	// We shouldn't close this one and it's used for later steps

	configPaths, _ := bh.GetPaths("configuration")

	for _, configPath := range configPaths {
		mpReader, err := reader.NewMPReader(configPath)
		if err != nil {
			bh.Log <- "❌ Error opening configuration file: " + err.Error()
			continue
		}
		defer mpReader.Close()

		totalInFile, err := mpReader.ReadLength()
		if err != nil {
			bh.Log <- "❌ Error reading length of configuration file: " + err.Error()
			continue
		}

		processedCount := 0
		batchCount := 0
		const progressInterval = 50

		originalEntry := new(ldap.Entry)
		var entry gildap.LDAPEntry

		if progressCallback != nil {
			progressCallback(0, totalInFile)
		}

		for i := 0; i < mpReader.Length(); i++ {
			if bh.IsAborted() {
				return
			}

			*originalEntry = ldap.Entry{}
			if err := mpReader.ReadEntry(originalEntry); err != nil {
				bh.Log <- "❌ Error decoding configuration entry: " + err.Error()
				continue
			}

			entry.Init(originalEntry)

			bh.processConfigurationEntry(&entry)

			processedCount++
			batchCount++

			if batchCount >= progressInterval {
				if progressCallback != nil {
					progressCallback(processedCount, totalInFile)
				}
				batchCount = 0
			}
		}

		if bh.IsAborted() {
			return
		}

		if progressCallback != nil {
			progressCallback(processedCount, totalInFile)
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
					MergeRemoteEnterpriseCACollection(enterpriseCA, remoteData)
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
func (bh *BH) LoadSchemaInfo(progressCallback func(count, total int)) {
	if bh.IsAborted() {
		return
	}

	schemaPaths, _ := bh.GetPaths("schema")

	for _, schemaPath := range schemaPaths {
		mpReader, err := reader.NewMPReader(schemaPath)
		if err != nil {
			bh.Log <- "❌ Error opening schema file: " + err.Error()
			continue
		}
		defer mpReader.Close()

		totalInFile, err := mpReader.ReadLength()
		if err != nil {
			bh.Log <- "❌ Error reading length of schema file: " + err.Error()
			continue
		}

		processedCount := 0

		originalEntry := new(ldap.Entry)
		var entry gildap.LDAPEntry

		if progressCallback != nil {
			progressCallback(0, totalInFile)
		}

		for i := 0; i < mpReader.Length(); i++ {
			if bh.IsAborted() {
				return
			}

			*originalEntry = ldap.Entry{}
			if err := mpReader.ReadEntry(originalEntry); err != nil {
				bh.Log <- "❌ Error decoding schema entry: " + err.Error()
				continue
			}

			entry.Init(originalEntry)

			name := entry.GetAttrVal("name", "")
			schemaIDGUID := entry.GetAttrRawVal("schemaIDGUID", []byte{})
			guidStr := gildap.BytesToGUID(schemaIDGUID)

			builder.BState().ObjectTypeGUIDMap.Store(strings.ToLower(name), guidStr)

			processedCount++

			if progressCallback != nil {
				progressCallback(processedCount, totalInFile)
			}
		}
	}
}

// CacheJob represents a cache loading job
type CacheJob struct {
	File  string
	Label string
}

// PerformConversion transforms LDAP data to BloodHound JSON format with progress tracking.
func (bh *BH) PerformConversion() {
	// Update timestamp for this conversion run
	bh.Timestamp = time.Now().Format("20060102150405")
	bh.generatedFiles = make([]string, 0)

	bh.UIApp.SetupConversionTable()

	var spinner *ui.Spinner
	spinner = ui.NewSingleTableSpinner(bh.UIApp, bh.UIApp.GetConversionTable(), 0)
	spinner.Start()
	defer spinner.Stop()

	abortLogged := false
	notifyAbort := func() bool {
		if bh.IsAborted() {
			if !abortLogged && bh.Log != nil {
				bh.Log <- "🛑 Conversion abort requested. Stopping remaining steps..."
				abortLogged = true
			}
			return true
		}
		return false
	}

	if notifyAbort() {
		return
	}

	// Initialize builder state if needed
	builder.BState().Init()

	if notifyAbort() {
		return
	}

	// Load remote collection results if available
	bh.RemoteComputerCollection = bh.loadRemoteComputerResults()
	bh.RemoteEnterpriseCACollection = bh.loadRemoteCAResults()

	// Load cache and schema (rows 1-2)
	bh.runConversionStep(spinner, 1, func() { bh.loadConversionCache() })
	if notifyAbort() {
		return
	}
	bh.runSchemaConversion(spinner, 2)
	if notifyAbort() {
		return
	}

	// Process domains and configuration (rows 3-4)
	bh.runDomainConversion(spinner, 3)
	if notifyAbort() {
		return
	}

	bh.runConfigurationConversion(spinner, 4)
	if notifyAbort() {
		return
	}

	// Process all object types (rows 5-10)
	gposPaths, _ := bh.GetPaths("gpos")
	bh.runObjectConversion(spinner, 5, gposPaths, "gpos")
	if notifyAbort() {
		return
	}

	ousPaths, _ := bh.GetPaths("ous")
	bh.runObjectConversion(spinner, 6, ousPaths, "ous")
	if notifyAbort() {
		return
	}

	containersPaths, _ := bh.GetPaths("containers")
	bh.runObjectConversion(spinner, 7, containersPaths, "containers")
	if notifyAbort() {
		return
	}

	groupsPaths, _ := bh.GetPaths("groups")
	bh.runObjectConversion(spinner, 8, groupsPaths, "groups")
	if notifyAbort() {
		return
	}

	computersPaths, _ := bh.GetPaths("computers")
	bh.runObjectConversion(spinner, 9, computersPaths, "computers")
	if notifyAbort() {
		return
	}

	usersPaths, _ := bh.GetPaths("users")
	bh.runObjectConversion(spinner, 10, usersPaths, "users")
	if notifyAbort() {
		return
	}

	// Compress output if enabled (row 11)
	if bh.RuntimeOptions.GetCompressOutput() {
		bh.runConversionStep(spinner, 11, func() { bh.compressBloodhoundOutput() })
	}

	if builder.BState().EmptySDCount > 0 {
		bh.Log <- fmt.Sprintf("🫠 [yellow]Security descriptors were not present in %d entries. Permissions issue during ingestion?[-]", builder.BState().EmptySDCount)
	}
}

// runConversionStep runs a conversion step and updates UI
func (bh *BH) runConversionStep(spinner *ui.Spinner, row int, stepFunc func()) {
	if bh.IsAborted() {
		return
	}

	if spinner != nil {
		spinner.SetRunningRow(row)
	}
	bh.UIApp.UpdateConversionRow(row, "", "-", "-", "-", "-", "-", "-")

	startTime := time.Now()
	stepFunc()
	elapsed := time.Since(startTime)

	if bh.IsAborted() {
		if spinner != nil {
			spinner.SetDone(row)
		}
		bh.UIApp.UpdateConversionRow(row, "[red]× Aborted", "-", "-", "-", "-", "-", elapsed.Round(time.Second).String())
		return
	}

	if spinner != nil {
		spinner.SetDone(row)
	}
	bh.UIApp.UpdateConversionRow(row, "[green]✓ Done", "", "", "-", "", "-", elapsed.Round(time.Second).String())
}

// runConversionWithProgress runs a conversion step with progress tracking
func (bh *BH) runConversionWithProgress(spinner *ui.Spinner, row int, workFunc func(progressCallback func(int, int))) {
	if bh.IsAborted() {
		return
	}

	if spinner != nil {
		spinner.SetRunningRow(row)
	}
	bh.UIApp.UpdateConversionRow(row, "", "0", "-", "-", "-", "-", "-")

	tracker := newConversionProgressTracker(row, bh.UIApp, bh.IsAborted)
	progressCallback := tracker.createProgressCallback()

	startTime := time.Now()
	workFunc(progressCallback)
	elapsed := time.Since(startTime)

	// Stop tracker to prevent any further progress updates
	tracker.stop()

	if bh.IsAborted() {
		if spinner != nil {
			spinner.SetDone(row)
		}
		bh.UIApp.UpdateConversionRow(row, "[red]× Aborted", "-", "-", "-", "-", "-", elapsed.Round(time.Second).String())
		return
	}

	if spinner != nil {
		spinner.SetDone(row)
	}
	bh.UIApp.UpdateConversionRow(row, "[green]✓ Done", "", "", "-", "", "-", elapsed.Round(time.Second).String())
}

// loadConversionCache loads all necessary caches for conversion
func (bh *BH) loadConversionCache() {
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
		var progressText string
		var percentText string
		var speedText string
		var avgSpeedText string
		var etaText string

		if totalEntries > 0 {
			if totalProcessed >= totalEntries {
				progressText = fmt.Sprintf("[green]%d/%d[-]", totalProcessed, totalEntries)
			} else {
				progressText = fmt.Sprintf("[blue]%d/%d[-]", totalProcessed, totalEntries)
			}
			percentage := float64(totalProcessed) / float64(totalEntries) * 100.0
			if percentage >= 100.0 {
				percentText = fmt.Sprintf("[green]%.1f%%[-]", percentage)
			} else {
				percentText = fmt.Sprintf("[blue]%.1f%%[-]", percentage)
			}
		} else {
			progressText = strconv.Itoa(totalProcessed)
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

		bh.UIApp.UpdateConversionRow(1, "", progressText, percentText, speedText, avgSpeedText, etaText, elapsed.Round(time.Second).String())
	}

	// Second pass: process all readers sequentially
	for _, info := range readers {
		if bh.IsAborted() {
			return
		}

		filePath := info.reader.GetPath()
		bh.Log <- fmt.Sprintf("📦 Loading %s", filePath)

		builder.BState().CacheEntries(info.reader, info.identifier, bh.Log, bh.IsAborted, progressCallback)

		// Mark this cache as loaded
		builder.BState().MarkCacheLoaded(filePath)

		bh.Log <- fmt.Sprintf("✅ %s loaded", filePath)
	}
}

// runSchemaConversion loads schema with progress tracking
func (bh *BH) runSchemaConversion(spinner *ui.Spinner, row int) {
	bh.runConversionWithProgress(spinner, row, func(progressCallback func(int, int)) {
		bh.LoadSchemaInfo(progressCallback)
	})
}

// runDomainConversion processes domains with progress tracking
func (bh *BH) runDomainConversion(spinner *ui.Spinner, row int) {
	bh.runConversionWithProgress(spinner, row, func(progressCallback func(int, int)) {
		bh.ProcessDomain(progressCallback)
	})
}

// runConfigurationConversion processes configuration with progress tracking
func (bh *BH) runConfigurationConversion(spinner *ui.Spinner, row int) {
	bh.runConversionWithProgress(spinner, row, func(progressCallback func(int, int)) {
		bh.ProcessConfiguration(progressCallback)
	})
}

// runObjectConversion processes objects of a specific kind
func (bh *BH) runObjectConversion(spinner *ui.Spinner, row int, files []string, kind string) {
	bh.runConversionWithProgress(spinner, row, func(progressCallback func(int, int)) {
		bh.ProcessObjects(files, kind, progressCallback)
	})
}
