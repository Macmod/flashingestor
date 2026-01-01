package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/Macmod/flashingestor/bloodhound"
	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/config"
	"github.com/Macmod/flashingestor/core"
	"github.com/Macmod/flashingestor/ui"
)

var versionString = "v1.0.0"

// Application entry point
func main() {
	cfg, err := config.ParseFlags()
	if err != nil {
		log.Fatal(err)
	}

	dirs, err := core.SetupDirectories(cfg.OutputDir)
	if err != nil {
		log.Fatal(err)
	}

	uiApp := ui.NewApplication()
	uiApp.SetRuntimeOptions(cfg.RuntimeOptions)

	jobManager := newJobManager()

	logChannel := make(chan string)
	logFunc := func(format string, args ...interface{}) {
		logChannel <- fmt.Sprintf(format, args...)
	}

	var logFile *os.File
	if cfg.LogFile != "" {
		logFile, err = core.OpenLogFile(cfg.LogFile)
		if err != nil {
			log.Fatal("Failed to open log file:", err)
		}
		defer logFile.Close()
	}

	logger := core.NewLogger(logChannel, logFile, uiApp)
	go logger.Start()

	logFunc("🧩 Welcome to FlashIngestor " + versionString)
	logFunc("⭕ [blue]Config file[-]: " + cfg.ConfigPath)
	logFunc("⭕ [blue]Output folder[-]: " + cfg.OutputDir)

	resolver := cfg.Resolver
	customDNS := cfg.CustomDns
	if customDNS != "" {
		if cfg.DnsTcp {
			logFunc("🔍 [blue]DNS protocol[-]: TCP")
		} else {
			logFunc("🔍 [blue]DNS protocol[-]: UDP")
		}

		logFunc("🔍 [blue]Custom DNS resolver[-]: \"" + customDNS + "\"")
	}

	logFunc("⭕ [blue]LDAP scheme[-]: " + cfg.LdapAuthOptions.Scheme)

	// Check if we have authentication credentials
	disableIngest := false
	if cfg.ChosenAuthIngest == "" {
		disableIngest = true
		logFunc("🫠 [red]No authentication credentials detected for ingestion. Ingestion will be disabled for this session.[-]")
	}

	disableRemote := cfg.ChosenAuthIngest == "" && cfg.ChosenAuthRemote == ""
	if disableRemote {
		logFunc("🫠 [red]No authentication credentials detected for remote collection. Remote collection will be disabled for this session.[-]")
	}

	bhInst := &bloodhound.BH{}
	bhInst.Init(
		dirs.LDAP, dirs.Remote, dirs.BloodHound, resolver,
		cfg.RemoteWorkers, cfg.DNSWorkers, cfg.RemoteTimeout, cfg.RuntimeOptions,
		logChannel,
		uiApp,
	)

	// Use RemoteAuthOptions for remote collection, fallback to StandardAuthOptions if not set
	if cfg.ChosenAuthIngest == "" {
		logFunc("🔗 [blue]Auth method (ingestion)[-]: None")
	} else {
		logFunc("🔗 [blue]Auth method (ingestion)[-]: " + cfg.ChosenAuthIngest)
	}

	if cfg.RuntimeOptions.GetRecurseTrusts() {
		if !slices.Contains([]string{"Password", "NTHash", "Anonymous"}, cfg.ChosenAuthIngest) || cfg.IngestAuth.Kerberos() {
			// Kerberos cross-realm auth should be feasible to implement,
			// but I don't know how yet :)
			logFunc("🫠 [yellow]RecurseTrusts disabled (not supported for this auth method)[-]")
			cfg.RuntimeOptions.SetRecurseTrusts(false)
		}
	}

	ingestMgr := IngestionManager{
		jobManager:          jobManager,
		ldapAuthOptions:     cfg.LdapAuthOptions,
		auth:                cfg.IngestAuth,
		resolver:            resolver,
		queryDefs:           cfg.RuntimeOptions.GetQueries(),
		ldapFolder:          dirs.LDAP,
		logFunc:             logFunc,
		ingestedDomains:     &sync.Map{},
		includeACLs:         cfg.RuntimeOptions.GetIncludeACLs(),
		recurseTrusts:       cfg.RuntimeOptions.GetRecurseTrusts(),
		recurseFeasibleOnly: cfg.RuntimeOptions.GetRecurseFeasibleOnly(),
		searchForest:        cfg.RuntimeOptions.GetSearchForest(),
		ldapsToLdapFallback: cfg.RuntimeOptions.GetLdapsToLdapFallback(),
	}

	conversionMgr := newConversionManager(bhInst, logFunc)
	remoteMgr := newRemoteCollectionManager(bhInst, cfg.RemoteAuth, logFunc)

	if cfg.ChosenAuthRemote == "" {
		logFunc("🔗 [blue]Auth method (remote collection)[-]: None")
	} else {
		logFunc("🔗 [blue]Auth method (remote collection)[-]: " + cfg.ChosenAuthRemote)
	}

	var initialDomain, initialBaseDN, initialDC string
	if !disableIngest {
		initialDomain = strings.ToUpper(cfg.IngestAuth.Creds().Domain)
		if initialDomain == "" {
			logFunc("❌ [red]Failed to determine initial domain for ingestion from the credentials. Check your credentials and try again.\n")
		} else {
			logFunc("🔗 [blue]Initial domain[-]: \"%s\"", initialDomain)

			initialBaseDN = "DC=" + strings.ReplaceAll(initialDomain, ".", ",DC=")
			logFunc("🔗 [blue]Inferred BaseDN[-]: \"%s\"", initialBaseDN)

			initialDC = cfg.DomainController
			logFunc("🔗 [blue]Initial DC[-]: \"%s\"", initialDC)
		}
	}

	var ingestionCallback, remoteCollectionCallback func()

	if !disableIngest {
		ingestionCallback = func() {
			// Reset ingested domains tracker for new run
			ingestMgr.ingestedDomains = &sync.Map{}

			// Mark initial domain as ingested
			ingestMgr.ingestedDomains.Store(strings.ToUpper(initialDomain), true)

			ctx := context.Background()
			ingestMgr.start(ctx, uiApp, initialDomain, initialBaseDN, initialDC)
		}
	}

	if !disableRemote {
		remoteCollectionCallback = func() {
			remoteMgr.start(uiApp)
		}
	}

	uiApp.SetButtonCallbacks(
		ingestionCallback,
		func() {
			conversionMgr.start(uiApp)
		},
		remoteCollectionCallback,
		func() {
			// Clear cache callback
			builder.BState().Clear()
			logFunc("✅ [green]Cache cleared successfully[-]")
		},
	)

	if disableIngest {
		uiApp.DisableIngestion()
	}

	if disableRemote {
		uiApp.DisableRemoteCollection()
	}

	if err := uiApp.Run(); err != nil {
		log.Fatal(err)
	}
}
