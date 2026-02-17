package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Macmod/flashingestor/config"
	"github.com/Macmod/flashingestor/core"
	gildap "github.com/Macmod/flashingestor/ldap"
	"github.com/Macmod/flashingestor/ui"
	"github.com/RedTeamPentesting/adauth"
	"github.com/RedTeamPentesting/adauth/ldapauth"
	"github.com/go-ldap/ldap/v3"
)

// DomainRequest holds parameters for domain ingestion.
type DomainRequest struct {
	DomainName       string
	BaseDN           string
	DomainController string
	SourceDomain     string
}

// JobManager handles the creation and management of LDAP query jobs.
type JobManager struct {
	jobs []gildap.QueryJob
}

// ForestCollectionStatus tracks which forest-wide data has been collected.
type ForestCollectionStatus struct {
	Configuration bool
	Schema        bool
}

// IngestionManager orchestrates multi-domain LDAP ingestion.
type IngestionManager struct {
	jobManager          *JobManager
	queryDefs           []config.QueryDefinition
	ldapAuthOptions     *ldapauth.Options
	auth                *config.CredentialMgr
	resolver            *config.CustomResolver
	ldapFolder          string
	logger              *core.Logger
	uiApp               *ui.Application
	domainQueue         chan DomainRequest
	trustEntriesChan    chan *ldap.Entry
	configEntriesChan   chan *ldap.Entry
	processedDomains    *sync.Map // tracks domains processed in current run
	forestStructure     *sync.Map // maps domain names to their forest root domain names
	collectedForests    *sync.Map // maps forest root to *ForestCollectionStatus
	startTime           time.Time
	domainCount         atomic.Int32 // tracks number of domains ingested
	pendingDomains      atomic.Int32 // tracks domains queued but not yet completed
	globalAborted       atomic.Bool  // tracks if ingestion has been aborted globally
	recurseTrusts       bool         // whether to recurse through trusts
	recurseFeasibleOnly bool         // only recurse feasible trusts (inbound trusts + transitive if beyond the 2nd level of trusts)
	searchForest        bool         // whether to search the forest configuration partition for additional domains
	includeACLs         bool         // whether to include nTSecurityDescriptor
	ldapsToLdapFallback bool         // whether to fallback from LDAPS to LDAP on connection failure
	appendForestDomains bool         // whether to append to existing forest domains file
	initialDomain       string       // the initial domain that started the ingestion
	ldapxFilter         string       // LDAP filter obfuscation middleware chain
	ldapxAttrs          string       // LDAP attributes obfuscation middleware chain
	ldapxBaseDN         string       // LDAP baseDN obfuscation middleware chain
}

// JobManager methods
func newJobManager() *JobManager {
	return &JobManager{}
}

func (jm *JobManager) initializeJobs(queryDefs []config.QueryDefinition, includeACLs bool, callback func(int, gildap.QueryJob)) []gildap.QueryJob {
	jm.jobs = make([]gildap.QueryJob, len(queryDefs))

	for idx, def := range queryDefs {
		// Filter out nTSecurityDescriptor if includeACLs is false
		attributes := make([]string, 0, len(def.Attributes))
		for _, attr := range def.Attributes {
			if strings.EqualFold(attr, "nTSecurityDescriptor") && !includeACLs {
				continue
			}
			attributes = append(attributes, attr)
		}

		job := gildap.QueryJob{
			Name:       def.Name,
			Filter:     def.Filter,
			Attributes: attributes,
			PageSize:   uint32(def.PageSize),
			Row:        idx + 1,
		}

		jm.jobs[idx] = job

		if callback != nil {
			callback(idx, job)
		}
	}

	return jm.jobs
}

// IngestionManager methods
// testLDAPConnection validates the LDAP connection with the provided credentials and target
// and retrieves the RootDN from RootDSE.
func (m *IngestionManager) testLDAPConnection(
	ctx context.Context,
	target *adauth.Target,
	ldapOptions *ldapauth.Options,
) (string, error) {
	var err error

	// Test the connection
	conn, err := ldapauth.ConnectTo(ctx, m.auth.Creds(), target, ldapOptions)
	if err != nil {
		return "", fmt.Errorf("LDAP connection failed: %w", err)
	}
	defer conn.Close()

	// Query RootDSE to get the DN of the forest root
	searchReq := ldap.NewSearchRequest(
		"", // empty base DN for RootDSE
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"rootDomainNamingContext"},
		nil,
	)

	searchRes, err := conn.Search(searchReq)
	if err != nil {
		return "", fmt.Errorf("RootDSE query failed: %w", err)
	}

	var rootDN string
	if searchRes != nil && len(searchRes.Entries) > 0 {
		rootDN = searchRes.Entries[0].GetAttributeValue("rootDomainNamingContext")
	}

	return rootDN, nil
}

// loadForestDomains loads existing forest domain mappings from ForestDomains.json
func (m *IngestionManager) loadForestDomains() {
	forestFile := filepath.Join(m.ldapFolder, "ForestDomains.json")
	file, err := os.Open(forestFile)
	if err != nil {
		return // File doesn't exist or can't be opened, skip loading
	}
	defer file.Close()

	var existingForest map[string]string
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&existingForest); err == nil {
		for domain, forestRoot := range existingForest {
			m.forestStructure.Store(domain, forestRoot)
		}
		m.logger.Log1("📂 [blue]Loaded %d existing forest domain mapping(s)[-]", len(existingForest))
	}
}

// saveForestDomains saves the current forest domain mappings to ForestDomains.json
func (m *IngestionManager) saveForestDomains() {
	forestMap := make(map[string]string)
	m.forestStructure.Range(func(key, value interface{}) bool {
		forestMap[key.(string)] = value.(string)
		return true
	})

	if len(forestMap) == 0 {
		return // Nothing to save
	}

	forestFile := filepath.Join(m.ldapFolder, "ForestDomains.json")
	file, err := os.Create(forestFile)
	if err != nil {
		m.logger.Log0("🫠 [yellow]Failed to create forest structure file: %v[-]", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(forestMap); err != nil {
		m.logger.Log0("🫠 [yellow]Failed to write forest structure: %v[-]", err)
	} else {
		if fileInfo, err := os.Stat(forestFile); err == nil {
			m.logger.Log1("✅ Saved %s (%s)", forestFile, core.FormatFileSize(fileInfo.Size()))
		}
	}
}

// checkMsgpackFilesExist checks if any .msgpack files exist in the LDAP folder
func (m *IngestionManager) checkMsgpackFilesExist() (bool, error) {
	entries, err := os.ReadDir(m.ldapFolder)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	// Check for .msgpack files in the root ldap folder or any subdirectories
	for _, entry := range entries {
		if entry.IsDir() {
			// Check subdirectories for msgpack files
			subDir := filepath.Join(m.ldapFolder, entry.Name())
			subEntries, err := os.ReadDir(subDir)
			if err != nil {
				continue
			}
			for _, subEntry := range subEntries {
				if !subEntry.IsDir() && strings.HasSuffix(strings.ToLower(subEntry.Name()), ".msgpack") {
					return true, nil
				}
			}
		} else if strings.HasSuffix(strings.ToLower(entry.Name()), ".msgpack") {
			return true, nil
		}
	}

	return false, nil
}

func (m *IngestionManager) start(
	ctx context.Context,
	initialDomain string,
	initialBaseDN string,
	initialDC string,
) {
	// Recreate channels for each ingestion run
	m.domainQueue = make(chan DomainRequest, 100)
	m.trustEntriesChan = make(chan *ldap.Entry, 100)
	m.configEntriesChan = make(chan *ldap.Entry, 100)

	// Reset counters for new ingestion run
	m.domainCount.Store(0)
	m.pendingDomains.Store(0)
	m.globalAborted.Store(false)
	m.initialDomain = strings.ToUpper(initialDomain)
	m.forestStructure = &sync.Map{}
	m.collectedForests = &sync.Map{}

	// Load existing forest domains
	m.loadForestDomains()

	m.startTime = time.Now()

	// Additional domain discovery
	go m.processTrustEntries()
	go m.processConfigurationEntries()

	m.pendingDomains.Add(1)

	newDomainRequest := DomainRequest{
		DomainName:       initialDomain,
		BaseDN:           initialBaseDN,
		DomainController: initialDC,
		SourceDomain:     "",
	}
	m.domainQueue <- newDomainRequest

	if !m.appendForestDomains {
		m.forestStructure = &sync.Map{}
	}

	go func() {
		m.uiApp.SetRunning(true, "ingestion")

		for req := range m.domainQueue {
			// Check if abort was requested before processing next domain
			if m.globalAborted.Load() {
				// Drain pending domains count
				if m.pendingDomains.Add(-1) == 0 {
					close(m.domainQueue)
				}
				continue
			}
			m.ingestDomain(ctx, req.DomainName, req.BaseDN, req.DomainController)
			m.logger.Log0("-")
		}

		// All domains have been processed, write forest structure and log final summary
		m.uiApp.SetRunning(false, "")

		if m.domainCount.Load() > 0 {
			m.saveForestDomains()

			totalDuration := time.Since(m.startTime)
			m.logger.Log0("🕝 [blue]Ingested %d domain(s) in %s[-]", m.domainCount.Load(), core.FormatDuration(totalDuration))
		} else {
			m.logger.Log0("🫠 [red]No domains were ingested.[-]")
		}
		m.logger.Log0("-")
	}()
}

func (m *IngestionManager) processConfigurationEntries() {
	var ldapEntry gildap.LDAPEntry

	for entryWithSource := range m.configEntriesChan {
		ldapEntry.Init(entryWithSource)

		objectClasses := ldapEntry.GetAttrVals("objectClass", []string{})
		if !slices.Contains(objectClasses, "crossRef") {
			continue
		} else {
			// systemFlags=3 means that
			// the crossRef represents an AD domain naming context
			// (not some other NC or weird partition)
			systemFlags := ldapEntry.GetAttrVal("systemFlags", "0")
			if systemFlags != "3" {
				continue
			}
		}

		sourceDomain := ldapEntry.GetDomainFromDN()
		domainName := ldapEntry.GetAttrVal("dnsRoot", "")
		if domainName == "" {
			continue
		}
		domainName = strings.ToUpper(domainName)

		// Check if already processed; if not, store as processed
		if _, loaded := m.processedDomains.LoadOrStore(domainName, true); loaded {
			continue
		}

		// Always show discovered forest domain
		m.logger.Log0("🔗 [green]New domain found in forest of \"%s\": \"%s\"[-]", sourceDomain, domainName)

		// Only add to queue if searchForest is enabled
		if !m.searchForest {
			m.logger.Log0("🦘 [yellow]Not queueing \"%s\" - search_forest is disabled[-]", domainName)
			continue
		}

		if m.globalAborted.Load() {
			continue
		}

		baseDN := m.inferBaseDN(domainName)
		m.pendingDomains.Add(1)

		newDomainRequest := DomainRequest{
			DomainName:       domainName,
			BaseDN:           baseDN,
			DomainController: "",
			SourceDomain:     sourceDomain,
		}
		m.domainQueue <- newDomainRequest

		m.logger.Log2("SearchForest DomainRequest: {\"domain\": \"%s\", \"basedn\": \"%s\", \"dc\": \"%s\", \"srcdom\": \"%s\"}", newDomainRequest.DomainName, newDomainRequest.BaseDN, newDomainRequest.DomainController, newDomainRequest.SourceDomain)
	}

	// All entries have been processed, close channel
	if m.configEntriesChan != nil {
		close(m.configEntriesChan)
	}
}

func (m *IngestionManager) processTrustEntries() {
	var ldapEntry gildap.LDAPEntry

	for entryWithSource := range m.trustEntriesChan {
		ldapEntry.Init(entryWithSource)

		trustName := ldapEntry.GetAttrVal("name", "")
		if trustName == "" {
			m.logger.Log0("🫠 [yellow]Skipping trust with missing name attribute[-]")
			continue
		}

		// Get source domain from the entry's DN (extract from CN=...,CN=System,DC=...)
		sourceDomain := ldapEntry.GetDomainFromDN()
		trustName = strings.ToUpper(trustName)

		// Check if already processed; if not, store as processed
		if _, loaded := m.processedDomains.LoadOrStore(trustName, true); loaded {
			continue
		}

		// Show discovered trust
		m.logger.Log0("🔗 [green]New domain found from \"%s\" trusts: \"%s\"[-]", sourceDomain, trustName)

		// Filter by trust direction + transitivity if recurse_feasible_only is enabled
		if m.recurseFeasibleOnly {
			trustDirectionStr := ldapEntry.GetAttrVal("trustDirection", "0")
			trustDirection := 0
			if val, err := strconv.Atoi(trustDirectionStr); err == nil {
				trustDirection = val
			}

			trustAttributesStr := ldapEntry.GetAttrVal("trustAttributes", "0")
			trustAttributes := 0
			if val, err := strconv.Atoi(trustAttributesStr); err == nil {
				trustAttributes = val
			}

			// Check if TRUST_DIRECTION_INBOUND (0x1) flag is absent
			if trustDirection&0x1 == 0 {
				m.logger.Log0(
					"🦘 [yellow]Skipping \"%s\" (DIR=%d,ATTR=%d) - recurse_feasible_only is enabled and it's not inbound[-]",
					trustName,
					trustDirection,
					trustAttributes,
				)
				continue
			}

			// For trusts from non-initial domains, also check transitivity
			if sourceDomain != "" && sourceDomain != m.initialDomain {
				// Check if TRUST_ATTRIBUTE_NON_TRANSITIVE (0x1) flag is set
				if trustAttributes&0x1 != 0 {
					m.logger.Log0(
						"🦘 [yellow]Skipping \"%s\" (DIR=%d,ATTR=%d) - recurse_feasible_only is enabled and it's nontransitive[-]",
						trustName,
						trustDirection,
						trustAttributes,
					)
					continue
				}
			}
		}

		// Only add to queue if recurseTrusts is enabled
		if !m.recurseTrusts {
			m.logger.Log0("🦘 [yellow]Not queueing \"%s\" - recurse_trusts is disabled[-]", trustName)
			continue
		}

		// Don't queue new domains if abort was requested
		if m.globalAborted.Load() {
			continue
		}

		baseDN := m.inferBaseDN(trustName)
		m.pendingDomains.Add(1)

		newDomainRequest := DomainRequest{
			DomainName:       trustName,
			BaseDN:           baseDN,
			DomainController: "",
			SourceDomain:     sourceDomain,
		}

		m.domainQueue <- newDomainRequest
		m.logger.Log2("RecurseTrusts DomainRequest: {\"domain\": \"%s\", \"basedn\": \"%s\", \"dc\": \"%s\", \"srcdom\": \"%s\"}", newDomainRequest.DomainName, newDomainRequest.BaseDN, newDomainRequest.DomainController, newDomainRequest.SourceDomain)
	}

	// All trusts have been processed, close channel
	if m.trustEntriesChan != nil {
		close(m.trustEntriesChan)
	}
}

func (m *IngestionManager) inferBaseDN(domainName string) string {
	if strings.Contains(domainName, ".") {
		parts := strings.Split(domainName, ".")
		dcParts := make([]string, len(parts))
		for i, part := range parts {
			dcParts[i] = "DC=" + part
		}
		return strings.Join(dcParts, ",")
	}
	return "DC=" + domainName
}

func (m *IngestionManager) discoverDC(ctx context.Context, domainName string) (string, error) {
	var discoveredDC string
	var dcHost string

	// SRV lookup for LDAP
	// Netlogon does not create _ldaps._tcp records, so we shouldn't check for these
	_, addrs, err := m.resolver.LookupSRV(ctx, "ldap", "tcp", domainName)

	port := 389
	if err == nil && len(addrs) > 0 {
		// Maybe the port was changed for crazy reasons?
		port = int(addrs[0].Port)
		if strings.EqualFold(m.ldapAuthOptions.Scheme, "ldaps") {
			port = 636
		}

		dcHost = strings.TrimRight(addrs[0].Target, ".")
		discoveredDC = dcHost + ":" + strconv.Itoa(port)
	}

	// Fallback to A record lookup if no SRV records found
	if dcHost == "" {
		dcAddrs, err := m.resolver.LookupIP(ctx, "ip", domainName)
		if err == nil {
			if len(dcAddrs) > 0 {
				dcHost = dcAddrs[0].String()

				if strings.EqualFold(m.ldapAuthOptions.Scheme, "ldaps") {
					discoveredDC = dcHost + ":636"
				} else {
					discoveredDC = dcHost + ":389"
				}
			}
		} else {
			return "", err
		}
	}

	if dcHost == "" {
		return "", fmt.Errorf("could not resolve domain name")
	}

	return discoveredDC, nil
}

func (m *IngestionManager) notifyIngestionSkipped(domainName string) {
	m.logger.Log0("🛑 [red]Skipping ingestion of \"%s\"[-]", domainName)

	// Update all rows to show "Skipped" status
	for _, job := range m.jobManager.jobs {
		m.uiApp.UpdateIngestRow(domainName, job.Row, "[yellow]- Skipped[-]", "-", "-", "-", "-", "-")
	}
}

func (m *IngestionManager) ingestDomain(ctx context.Context, domainName, baseDN, domainController string) {
	m.uiApp.AddDomainTab(domainName)
	m.uiApp.SwitchToDomainTab(domainName)
	m.uiApp.InsertIngestHeader(domainName)

	currentDomainFolder := filepath.Join(m.ldapFolder, domainName)
	if err := os.MkdirAll(currentDomainFolder, 0755); err != nil {
		m.logger.Log0("❌ Failed to create domain folder: %v", err)
		m.notifyIngestionSkipped(domainName)
		return
	}

	jobs := m.jobManager.initializeJobs(m.queryDefs, m.includeACLs, nil)
	spinner := ui.NewSpinner(m.uiApp, jobs, 0)
	spinner.RegisterDomain(domainName, m.uiApp.GetDomainTable(domainName))

	for _, job := range jobs {
		m.uiApp.SetupIngestRow(domainName, job.Row, job.Name)
	}

	var aborted atomic.Bool
	ctx, cancel := context.WithCancel(ctx)

	m.uiApp.SetAbortCallback(func() {
		if aborted.CompareAndSwap(false, true) {
			m.logger.Log0("🛑 [red]Abort requested for LDAP ingestion...[-]")
			m.globalAborted.Store(true) // Set global abort flag
			cancel()
		}
	})

	defer func() {
		spinner.Stop()
		cancel()
		m.uiApp.SetAbortCallback(nil)

		// Track completion and close queue when all domains are done
		if m.pendingDomains.Add(-1) == 0 {
			close(m.domainQueue)
		}
	}()

	updates := make(chan gildap.ProgressUpdate)
	ingestStartTime := time.Now()

	spinner.Start()

	// Test LDAP connection before starting ingestion for this domain
	m.logger.Log0("🔍 [blue]Testing LDAP connection to DC for \"%s\"...[-]", domainName)
	m.logger.Log0("🔗 [blue]Credential:[-] \"%s@%s\"", m.auth.Creds().Username, m.auth.Creds().Domain)
	if domainController == "" {
		dnsCtx, dnsCancel := context.WithTimeout(ctx, config.DNS_DIAL_TIMEOUT)
		defer dnsCancel()

		discoveredDC, err := m.discoverDC(dnsCtx, domainName)
		if err != nil {
			m.logger.Log0("❌ [red]Failed to discover DC for \"%s\": %v[-]", domainName, err)
			m.notifyIngestionSkipped(domainName)
			return
		}

		domainController = discoveredDC
		m.logger.Log0("🔗 [blue]Discovered DC:[-] \"%s\"", domainController)
	} else {
		m.logger.Log0("🔗 [blue]Provided DC:[-] \"%s\"", domainController)
	}

	ldapOptions := m.ldapAuthOptions
	target := m.auth.NewTarget(m.ldapAuthOptions.Scheme, domainController)

	testCtx, testCancel := context.WithTimeout(ctx, config.DEFAULT_LDAP_TIMEOUT)
	defer testCancel()

	var rootDN string
	var err error

	rootDN, err = m.testLDAPConnection(testCtx, target, ldapOptions)
	if err != nil {
		// Check if fallback is enabled and we're using LDAPS
		if m.ldapsToLdapFallback && strings.EqualFold(ldapOptions.Scheme, "ldaps") {
			m.logger.Log0("🤔 [yellow]LDAPS connection failed for \"%s\", attempting LDAP fallback...[-]", domainName)

			// Update domain controller port from 636 to 389 if needed
			ldapDC := domainController
			if strings.HasSuffix(domainController, ":636") {
				ldapDC = strings.TrimSuffix(domainController, ":636") + ":389"
			}

			// Change scheme to LDAP
			fallbackLdapOptions := *ldapOptions
			fallbackLdapOptions.Scheme = "ldap"
			ldapTarget := m.auth.NewTarget(fallbackLdapOptions.Scheme, ldapDC)

			// Test LDAP connection
			testCtx2, testCancel2 := context.WithTimeout(ctx, config.DEFAULT_LDAP_TIMEOUT)
			defer testCancel2()

			rootDN, err = m.testLDAPConnection(testCtx2, ldapTarget, &fallbackLdapOptions)
			if err == nil {
				m.logger.Log0("✅ [green]LDAP fallback successful for \"%s\"[-]", domainName)
				// Use the LDAP target and update LDAP options
				target = ldapTarget
				ldapOptions = &fallbackLdapOptions
			} else {
				m.logger.Log0("❌ [red]LDAP fallback also failed for \"%s\": %v[-]", domainName, err)
				m.notifyIngestionSkipped(domainName)
				return
			}
		} else {
			m.logger.Log0("❌ [red]LDAP connection test failed for \"%s\": %v[-]", domainName, err)
			m.notifyIngestionSkipped(domainName)
			return
		}
	}

	m.logger.Log0("✅ [green]LDAP connection test successful for \"%s\"[-]", domainName)
	forestRoot := ""
	forestRootFolder := ""
	var forestStatus *ForestCollectionStatus
	if rootDN != "" {
		forestRoot = gildap.DistinguishedNameToDomain(rootDN)
		forestRootFolder = filepath.Join(m.ldapFolder, "FOREST+"+forestRoot)
		if err := os.MkdirAll(forestRootFolder, 0755); err != nil {
			m.logger.Log0("❌ Failed to create domain folder: %v", err)
			return
		}

		// Store forest structure
		m.forestStructure.Store(strings.ToUpper(domainName), strings.ToUpper(forestRoot))

		// Tell the user about the forest root
		if strings.EqualFold(baseDN, rootDN) {
			m.logger.Log0("🔗 [blue]Domain \"%s\" is the root of its' forest[-]", domainName)
		} else {
			m.logger.Log0("🔗 [blue]Forest root for \"%s\"[-]: \"%s\"", domainName, forestRoot)
		}

		// Get or create forest collection status
		forestKey := strings.ToUpper(forestRoot)
		statusVal, _ := m.collectedForests.LoadOrStore(forestKey, &ForestCollectionStatus{})
		forestStatus = statusVal.(*ForestCollectionStatus)

		if forestStatus.Configuration || forestStatus.Schema {
			skipped := []string{}
			if forestStatus.Configuration {
				skipped = append(skipped, "Configuration")
			}
			if forestStatus.Schema {
				skipped = append(skipped, "Schema")
			}
			m.logger.Log0("🦘 [yellow]%s already collected for forest \"%s\", skipping...[-]", strings.Join(skipped, " and "), forestRoot)
		}
	} else {
		m.logger.Log0("🫠 [yellow]Could not determine forest root for \"%s\". Skipping forest-related ingestion...[-]", domainName)
	}

	m.logger.Log0("🚀 [cyan]Starting LDAP ingestion of \"%s\"...[-]", domainName)

	for i, job := range jobs {
		// For forest-wide queries, save in forest root folder if available;
		// skip if forest root unavailable or already collected
		if job.Name == "Configuration" {
			jobs[i].BaseDN = "CN=Configuration," + rootDN
			jobs[i].OutputFile = filepath.Join(forestRootFolder, "Configuration.msgpack")
		} else if job.Name == "Schema" {
			jobs[i].BaseDN = "CN=Schema,CN=Configuration," + rootDN
			jobs[i].OutputFile = filepath.Join(forestRootFolder, "Schema.msgpack")
		} else {
			jobs[i].BaseDN = baseDN
			jobs[i].OutputFile = filepath.Join(currentDomainFolder, jobs[i].Name+".msgpack")
		}
	}

	// Launch progress handler, then launch jobs
	var progressWg sync.WaitGroup
	progressWg.Add(1)
	go func() {
		defer progressWg.Done()
		m.handleProgressUpdates(updates, jobs, domainName, forestRoot, &aborted, ingestStartTime)
	}()

	var wg sync.WaitGroup
	for i, job := range jobs {
		// Skip forest-wide jobs if already collected
		if job.Name == "Configuration" && (forestRootFolder == "" || (forestStatus != nil && forestStatus.Configuration)) {
			m.uiApp.UpdateIngestRow(domainName, job.Row, "[yellow]- Skipped[-]", "-", "-", "-", "-", "-")
			continue
		}
		if job.Name == "Schema" && (forestRootFolder == "" || (forestStatus != nil && forestStatus.Schema)) {
			m.uiApp.UpdateIngestRow(domainName, job.Row, "[yellow]- Skipped[-]", "-", "-", "-", "-", "-")
			continue
		}

		wg.Add(1)
		spinner.SetRunning(domainName, i, true)

		// Log original query
		m.logger.Log2(
			"🎡 Collecting \"[blue]%s[-]\" for domain \"[blue]%s[-]\":\n    [blue]Filter[-]: %s\n    [blue]Attributes[-]: %s\n    [blue]BaseDN[-]: %s",
			job.Name, domainName, job.Filter,
			strings.Join(job.Attributes, ","), job.BaseDN,
		)

		// Apply LDAP obfuscation if configured
		obfuscatedJob := job
		hasObfuscation := false
		if m.ldapxFilter != "" {
			obfuscatedJob.Filter = applyFilterObfuscation(job.Filter, m.ldapxFilter)
			hasObfuscation = true
		}
		if m.ldapxAttrs != "" {
			obfuscatedJob.Attributes = applyAttrListObfuscation(job.Attributes, m.ldapxAttrs)
			hasObfuscation = true
		}
		if m.ldapxBaseDN != "" {
			obfuscatedJob.BaseDN = applyBaseDNObfuscation(job.BaseDN, m.ldapxBaseDN)
			hasObfuscation = true
		}

		// Log obfuscated query if obfuscation was applied
		if hasObfuscation {
			m.logger.Log2(
				"🎡 Obfuscated \"[purple]%s[-]\" for domain \"[purple]%s[-]\":\n    [purple]Filter[-]: %s\n    [purple]Attributes[-]: %s\n    [purple]BaseDN[-]: %s",
				obfuscatedJob.Name, domainName, obfuscatedJob.Filter,
				strings.Join(obfuscatedJob.Attributes, ","), obfuscatedJob.BaseDN,
			)
		}

		go func(j gildap.QueryJob, jobIndex int) {
			m.runJob(
				ctx, m.auth.Creds(), target, ldapOptions,
				j, jobIndex, domainName,
				spinner, updates, &wg,
			)
			m.logger.Log2(
				"🎡 Finished \"[blue]%s[-]\" for domain \"[blue]%s[-]\"",
				j.Name, domainName,
			)
		}(obfuscatedJob, i)
	}

	wg.Wait()
	close(updates)

	m.domainCount.Add(1)

	progressWg.Wait() // Wait for all progress updates to be processed
}

func (m *IngestionManager) handleProgressUpdates(updates chan gildap.ProgressUpdate, jobs []gildap.QueryJob, domainName, forestRoot string, aborted *atomic.Bool, ingestStartTime time.Time) {
	errorCount := 0

	// Helper to mark forest-wide collection status
	setForestStatus := func(jobName string, collected bool) {
		if forestRoot == "" || (jobName != "Configuration" && jobName != "Schema") {
			return
		}

		statusVal, ok := m.collectedForests.Load(strings.ToUpper(forestRoot))
		if !ok {
			return
		}

		forestStatus := statusVal.(*ForestCollectionStatus)
		if jobName == "Configuration" {
			forestStatus.Configuration = collected
		} else {
			forestStatus.Schema = collected
		}
	}

	for update := range updates {
		elapsed := update.Elapsed.Round(10 * time.Millisecond).String()
		jobName := jobs[update.Row-1].Name

		if update.Aborted {
			m.uiApp.UpdateIngestRow(domainName, update.Row, "[red]× Aborted", "", fmt.Sprintf("%d", update.Total), "", "", elapsed)
			setForestStatus(jobName, false)
			continue
		}

		if update.Err != nil {
			errorCount++
			m.uiApp.UpdateIngestRow(domainName, update.Row, "[red]× Error[-]", "", "", "-", "", "-")
			m.logger.Log0("❌ [red]Error during ingestion of job \"%s\": %s[-]", jobName, update.Err.Error())
			setForestStatus(jobName, false)
			continue
		}

		if update.Done {
			m.uiApp.UpdateIngestRow(domainName, update.Row, "[green]✓ Done", "", fmt.Sprintf("%d", update.Total), "-", "", elapsed)
			outputFile := jobs[update.Row-1].OutputFile
			if outputFile != "" {
				if fileInfo, err := os.Stat(outputFile); err == nil {
					m.logger.Log1("✅ Saved %s (%s)", outputFile, core.FormatFileSize(fileInfo.Size()))
					setForestStatus(jobName, true)
				} else {
					m.logger.Log0("🫠 [yellow]Problem saving %s[-]", outputFile)
				}
			}
		} else {
			m.uiApp.UpdateIngestRow(domainName, update.Row, "", fmt.Sprintf("%d", update.Page), fmt.Sprintf("%d", update.Total), fmt.Sprintf("%.1f", update.Speed), fmt.Sprintf("%.1f", update.AvgSpeed), elapsed)
		}
	}

	ingestDuration := time.Since(ingestStartTime)
	if aborted.Load() {
		m.logger.Log0("🛑 [red]Ingestion aborted after %s. Results may be incomplete.[-]", core.FormatDuration(ingestDuration))
	} else if errorCount > 0 {
		stepWord := "step"
		if errorCount > 1 {
			stepWord = "steps"
		}
		m.logger.Log0("🫠 [yellow]Ingestion of \"%s\" completed with errors in %d %s. Results may be incomplete.[-]", domainName, errorCount, stepWord)
	} else {
		m.logger.Log0("✅ [green]Ingestion of \"%s\" completed in %s[-]", domainName, core.FormatDuration(ingestDuration))
	}
}

func (m *IngestionManager) runJob(ctx context.Context, creds *adauth.Credential, target *adauth.Target, ldapOptions *ldapauth.Options, job gildap.QueryJob, jobIndex int, domainName string, spinner *ui.Spinner, updates chan gildap.ProgressUpdate, wg *sync.WaitGroup) {
	conn, err := ldapauth.ConnectTo(ctx, creds, target, ldapOptions)
	if err != nil {
		spinner.SetRunning(domainName, jobIndex, false)
		updates <- gildap.ProgressUpdate{Row: job.Row, Err: err}
		wg.Done()
		return
	}
	defer conn.Close()

	var entriesChan chan<- *ldap.Entry
	if job.Name == "Trusts" {
		entriesChan = m.trustEntriesChan
	} else if job.Name == "Configuration" {
		entriesChan = m.configEntriesChan
	}

	gildap.PagedSearchWorker(ctx, conn, job, updates, entriesChan, wg)
	spinner.SetRunning(domainName, jobIndex, false)
}
