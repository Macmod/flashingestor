package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
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

// IngestionManager orchestrates multi-domain LDAP ingestion.
type IngestionManager struct {
	jobManager          *JobManager
	queryDefs           []config.QueryDefinition
	ldapAuthOptions     *ldapauth.Options
	auth                *config.CredentialMgr
	resolver            *net.Resolver
	ldapFolder          string
	logFunc             func(string, ...interface{})
	domainQueue         chan DomainRequest
	trustEntriesChan    chan *ldap.Entry
	ingestedDomains     *sync.Map // tracks domains processed in current run
	ingestionStartTime  time.Time
	domainCount         atomic.Int32 // tracks number of domains ingested
	pendingDomains      atomic.Int32 // tracks domains queued but not yet completed
	globalAborted       atomic.Bool  // tracks if ingestion has been aborted globally
	recurseDomains      bool         // whether to recurse through trusts
	recurseFeasibleOnly bool         // only recurse feasible trusts (inbound trusts + transitive if beyond the 2nd level of trusts)
	includeACLs         bool         // whether to include nTSecurityDescriptor
	initialDomain       string       // the initial domain that started the ingestion
}

// JobManager methods
func newJobManager() *JobManager {
	return &JobManager{}
}

func (jm *JobManager) initializeJobs(baseDN, outputDir string, queryDefs []config.QueryDefinition, includeACLs bool, callback func(int, gildap.QueryJob)) []gildap.QueryJob {
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
			BaseDN:     config.GetBaseDNForQuery(def.Name, baseDN),
			Filter:     def.Filter,
			Attributes: attributes,
			PageSize:   uint32(def.PageSize),
			Row:        idx + 1,
			OutputFile: filepath.Join(outputDir, def.Name+".msgpack"),
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
func (m *IngestionManager) testLDAPConnection(
	ctx context.Context,
	target *adauth.Target,
) error {
	var err error

	creds := m.auth.Creds()
	if creds.Username == "" && creds.Password == "" {
		// Switch to SimpleBind only to allow for anonymous binds
		m.ldapAuthOptions.SimpleBind = true
	}

	// Test the connection
	conn, err := ldapauth.ConnectTo(ctx, creds, target, m.ldapAuthOptions)
	if err != nil {
		return fmt.Errorf("LDAP connection failed: %w", err)
	}
	defer conn.Close()

	return nil
}

func (m *IngestionManager) start(
	ctx context.Context,
	uiApp *ui.Application,
	initialDomain string,
	initialBaseDN string,
	initialDC string,
) {
	// Recreate channels for each ingestion run
	m.domainQueue = make(chan DomainRequest, 100)
	if m.recurseDomains {
		m.trustEntriesChan = make(chan *ldap.Entry, 100)
	}

	// Reset counters for new ingestion run
	m.domainCount.Store(0)
	m.pendingDomains.Store(0)
	m.globalAborted.Store(false)
	m.initialDomain = strings.ToUpper(initialDomain)

	m.ingestionStartTime = time.Now()
	go m.processTrustEntries()

	m.pendingDomains.Add(1)
	m.domainQueue <- DomainRequest{
		DomainName:       initialDomain,
		BaseDN:           initialBaseDN,
		DomainController: initialDC,
		SourceDomain:     "",
	}

	go func() {
		for req := range m.domainQueue {
			// Check if abort was requested before processing next domain
			if m.globalAborted.Load() {
				// Drain pending domains count
				if m.pendingDomains.Add(-1) == 0 {
					close(m.domainQueue)
				}
				continue
			}
			m.ingestDomain(ctx, uiApp, req.DomainName, req.BaseDN, req.DomainController)
		}

		// All domains have been processed, log final summary
		if m.domainCount.Load() > 0 {
			totalDuration := time.Since(m.ingestionStartTime)
			m.logFunc("🕝 [blue]Ingested %d domain(s) in %s[-]", m.domainCount.Load(), core.FormatDuration(totalDuration))
		} else {
			m.logFunc("🫠 [red]No domains were ingested.[-]")
		}
	}()
}

func (m *IngestionManager) processTrustEntries() {
	for entryWithSource := range m.trustEntriesChan {
		var ldapEntry gildap.LDAPEntry
		ldapEntry.Init(entryWithSource)

		trustName := ldapEntry.GetAttrVal("name", "")
		if trustName == "" {
			continue
		}

		// Get source domain from the entry's DN (extract from CN=...,CN=System,DC=...)
		sourceDomain := ldapEntry.GetDomainFromDN()

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
				m.logFunc(
					"[yellow]🤷🏼 Skipping \"%s\" (DIR=%d,ATTR=%d) as recurse_feasible_only is enabled.[-]",
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
					m.logFunc(
						"[yellow]🤷🏼 Skipping \"%s\" (DIR=%d,ATTR=%d) as recurse_feasible_only is enabled and it's nontransitive.[-]",
						trustName,
						trustDirection,
						trustAttributes,
					)
					continue
				}
			}
		}

		trustName = strings.ToUpper(trustName)

		// Skip if already ingested in this run
		if _, loaded := m.ingestedDomains.LoadOrStore(trustName, true); loaded {
			//m.logFunc("⏭ [yellow]Skipping already-ingested domain: \"%s\"[-]", trustName)
			continue
		}

		// Don't queue new domains if abort was requested
		if m.globalAborted.Load() {
			continue
		}

		baseDN := m.inferBaseDN(trustName)
		m.logFunc("🔗 [green]Domain found from \"%s\" trusts: \"%s\"[-]", sourceDomain, trustName)

		m.pendingDomains.Add(1)
		m.domainQueue <- DomainRequest{
			DomainName:       trustName,
			BaseDN:           baseDN,
			DomainController: "",
			SourceDomain:     sourceDomain,
		}
	}

	// All trusts have been processed, close channel if recursing
	if m.recurseDomains {
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

	// SRV lookups for LDAP / LDAPS
	_, addrs, err := m.resolver.LookupSRV(ctx, m.ldapAuthOptions.Scheme, "tcp", domainName)
	if err != nil {
		if strings.EqualFold(m.ldapAuthOptions.Scheme, "ldaps") {
			_, addrs, srvLDAPErr := m.resolver.LookupSRV(ctx, "ldap", "tcp", domainName)
			if srvLDAPErr == nil && len(addrs) > 0 {
				dcHost = strings.TrimRight(addrs[0].Target, ".")
				discoveredDC = dcHost + ":636"
			}
		}
	} else if len(addrs) > 0 {
		dcHost = strings.TrimRight(addrs[0].Target, ".")
		discoveredDC = dcHost + ":" + strconv.Itoa(int(addrs[0].Port))
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

func (m *IngestionManager) ingestDomain(ctx context.Context, uiApp *ui.Application, domainName, baseDN, domainController string) {
	uiApp.AddDomainTab(domainName)
	uiApp.SwitchToDomainTab(domainName)
	uiApp.InsertIngestHeader(domainName)

	currentDomainFolder := filepath.Join(m.ldapFolder, domainName)
	if err := os.MkdirAll(currentDomainFolder, 0755); err != nil {
		m.logFunc("❌ Failed to create domain folder: %v", err)
		return
	}

	jobs := m.jobManager.initializeJobs(baseDN, currentDomainFolder, m.queryDefs, m.includeACLs, nil)
	spinner := ui.NewSpinner(uiApp, jobs, 0)
	spinner.RegisterDomain(domainName, uiApp.GetDomainTable(domainName))

	for _, job := range jobs {
		uiApp.SetupIngestRow(domainName, job.Row, job.Name)
	}

	var aborted atomic.Bool
	ctx, cancel := context.WithCancel(ctx)

	uiApp.SetAbortCallback(func() {
		if aborted.CompareAndSwap(false, true) {
			m.logFunc("🛑 [red]Abort requested for LDAP ingestion...[-]")
			m.globalAborted.Store(true) // Set global abort flag
			cancel()
		}
	})

	uiApp.SetRunning(true, "ingestion")

	defer func() {
		spinner.Stop()
		cancel()
		uiApp.SetAbortCallback(nil)
		uiApp.SetRunning(false, "")

		// Track completion and close queue when all domains are done
		if !aborted.Load() {
			if m.pendingDomains.Add(-1) == 0 {
				close(m.domainQueue)
			}
		}
	}()

	updates := make(chan gildap.ProgressUpdate)
	ingestStartTime := time.Now()

	var progressWg sync.WaitGroup
	progressWg.Add(1)
	go func() {
		defer progressWg.Done()
		m.handleProgressUpdates(uiApp, updates, jobs, domainName, &aborted, ingestStartTime)
	}()

	spinner.Start()

	// Test LDAP connection before starting ingestion for this domain
	m.logFunc("🔍 [blue]Testing LDAP connection to DC for \"%s\"...[-]", domainName)
	m.logFunc("🔗 [blue]Credential:[-] \"%s@%s\"", m.auth.Creds().Username, m.auth.Creds().Domain)
	if domainController == "" {
		dnsCtx, dnsCancel := context.WithTimeout(ctx, config.DNS_DIAL_TIMEOUT)
		defer dnsCancel()

		discoveredDC, err := m.discoverDC(dnsCtx, domainName)
		if err != nil {
			m.logFunc("❌ [red]Failed to discover DC for \"%s\": %v[-]", domainName, err)
			return
		}

		domainController = discoveredDC
		m.logFunc("🔗 [blue]Discovered DC:[-] \"%s\"", domainController)
	} else {
		m.logFunc("🔗 [blue]Provided DC:[-] \"%s\"", domainController)
	}

	target := m.auth.NewTarget(m.ldapAuthOptions.Scheme, domainController)

	testCtx, testCancel := context.WithTimeout(ctx, config.DEFAULT_LDAP_TIMEOUT)
	defer testCancel()

	err := m.testLDAPConnection(testCtx, target)
	if err != nil {
		m.logFunc("❌ [red]LDAP connection test failed for \"%s\": %v[-]", domainName, err)
		m.logFunc("🛑 [red]Skipping ingestion of \"%s\"[-]", domainName)

		// Update all rows to show "Skipped" status
		for _, job := range jobs {
			uiApp.UpdateIngestRow(domainName, job.Row, "[red]🛑 Skipped[-]", "", "", "", "", "")
		}

		return
	}

	m.logFunc("✅ [green]LDAP connection test successful for \"%s\"[-]", domainName)

	m.logFunc("🚀 [cyan]Starting LDAP ingestion of \"%s\"...[-]", domainName)
	/*
		m.logFunc(fmt.Sprintf("CREDS %v\n", creds))
		m.logFunc(fmt.Sprintf("TARGET %v\n", target))
	*/

	var wg sync.WaitGroup
	for i, job := range jobs {
		wg.Add(1)
		spinner.SetRunning(domainName, i, true)
		go func(j gildap.QueryJob, jobIndex int) {
			m.runJob(ctx, m.auth.Creds(), target, j, jobIndex, domainName, spinner, updates, &wg)
		}(job, i)
	}

	wg.Wait()
	close(updates)

	m.domainCount.Add(1)

	progressWg.Wait() // Wait for all progress updates to be processed
}

func (m *IngestionManager) handleProgressUpdates(uiApp *ui.Application, updates chan gildap.ProgressUpdate, jobs []gildap.QueryJob, domainName string, aborted *atomic.Bool, ingestStartTime time.Time) {
	errorCount := 0

	for update := range updates {
		if update.Aborted {
			uiApp.UpdateIngestRow(domainName, update.Row, "[red]× Aborted", "", fmt.Sprintf("%d", update.Total), "", "", update.Elapsed.Round(time.Second).String())
			continue
		}

		if update.Err != nil {
			errorCount++
			uiApp.UpdateIngestRow(domainName, update.Row, "[red]× Error[-]", "", "", "-", "", "-")
			m.logFunc("❌ [red]Error during ingestion of job \"%s\": %s[-]", jobs[update.Row-1].Name, update.Err.Error())
			continue
		}

		if update.Done {
			uiApp.UpdateIngestRow(domainName, update.Row, "[green]✓ Done", "", fmt.Sprintf("%d", update.Total), "-", "", update.Elapsed.Round(time.Second).String())
			if update.OutputFile != "" {
				if fileInfo, err := os.Stat(update.OutputFile); err == nil {
					m.logFunc("✅ Saved %s (%s)", update.OutputFile, core.FormatFileSize(fileInfo.Size()))
				} else {
					m.logFunc("🫠 [yellow]Problem saving %s[-]", update.OutputFile)
				}
			}
		} else {
			uiApp.UpdateIngestRow(domainName, update.Row, "", fmt.Sprintf("%d", update.Page), fmt.Sprintf("%d", update.Total), fmt.Sprintf("%.1f", update.Speed), fmt.Sprintf("%.1f", update.AvgSpeed), update.Elapsed.Round(time.Second).String())
		}
	}

	ingestDuration := time.Since(ingestStartTime)
	if aborted.Load() {
		m.logFunc("🛑 [red]Ingestion aborted after %s. Results may be incomplete.[-]", core.FormatDuration(ingestDuration))
	} else if errorCount > 0 {
		stepWord := "step"
		if errorCount > 1 {
			stepWord = "steps"
		}
		m.logFunc("🫠 [yellow]Ingestion of \"%s\" completed with errors in %d %s. Results may be incomplete.[-]", domainName, errorCount, stepWord)
	} else {
		m.logFunc("✅ [green]Ingestion of \"%s\" completed in %s[-]", domainName, core.FormatDuration(ingestDuration))
	}
}

func (m *IngestionManager) runJob(ctx context.Context, creds *adauth.Credential, target *adauth.Target, job gildap.QueryJob, jobIndex int, domainName string, spinner *ui.Spinner, updates chan gildap.ProgressUpdate, wg *sync.WaitGroup) {
	conn, err := ldapauth.ConnectTo(ctx, creds, target, m.ldapAuthOptions)
	if err != nil {
		spinner.SetRunning(domainName, jobIndex, false)
		updates <- gildap.ProgressUpdate{Row: job.Row, Err: err}
		wg.Done()
		return
	}
	defer conn.Close()

	var entriesChan chan<- *ldap.Entry
	if job.Name == "Trusts" && m.trustEntriesChan != nil {
		entriesChan = m.trustEntriesChan
	}

	gildap.PagedSearchWorker(ctx, conn, job, updates, entriesChan, wg)
	spinner.SetRunning(domainName, jobIndex, false)
}
