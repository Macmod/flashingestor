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

var (
	version = "0.1.0"
)

// Application entry point
func main() {
	cfg, err := config.ParseFlags()
	if err != nil {
		if err.Error() == "VERSION_REQUESTED" {
			printVersion()
			os.Exit(0)
		}
		log.Fatal(err)
	}

	dirs, err := core.SetupDirectories(cfg.OutputDir)
	if err != nil {
		log.Fatal(err)
	}

	uiApp := ui.NewApplication()
	uiApp.SetRuntimeOptions(cfg.RuntimeOptions)

	jobManager := newJobManager()

	logChannel := make(chan core.LogMessage)
	logFunc := func(format string, args ...interface{}) {
		logChannel <- core.LogMessage{Message: fmt.Sprintf(format, args...), Level: 0}
	}
	logVerbose := func(format string, args ...interface{}) {
		logChannel <- core.LogMessage{Message: fmt.Sprintf(format, args...), Level: 1}
	}

	var logFile *os.File
	if cfg.LogFile != "" {
		logFile, err = core.OpenLogFile(cfg.LogFile)
		if err != nil {
			log.Fatal("Failed to open log file:", err)
		}
		defer logFile.Close()
	}

	verboseLevel := cfg.RuntimeOptions.GetVerbose()
	logger := core.NewLogger(logChannel, logFile, uiApp, verboseLevel)
	go logger.Start()

	logFunc("🧩 Welcome to FlashIngestor " + version)
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
		logVerbose:          logVerbose,
		uiApp:               uiApp,
		processedDomains:    &sync.Map{},
		includeACLs:         cfg.RuntimeOptions.GetIncludeACLs(),
		recurseTrusts:       cfg.RuntimeOptions.GetRecurseTrusts(),
		recurseFeasibleOnly: cfg.RuntimeOptions.GetRecurseFeasibleOnly(),
		searchForest:        cfg.RuntimeOptions.GetSearchForest(),
		ldapsToLdapFallback: cfg.RuntimeOptions.GetLdapsToLdapFallback(),
		appendForestDomains: cfg.RuntimeOptions.GetAppendForestDomains(),
	}

	conversionMgr := newConversionManager(bhInst, logFunc)
	remoteMgr := newRemoteCollectionManager(bhInst, cfg.RemoteAuth, logFunc)

	if cfg.ChosenAuthRemote == "" {
		logFunc("🔗 [blue]Auth method (remote collection)[-]: None")
	} else {
		logFunc("🔗 [blue]Auth method (remote collection)[-]: " + cfg.ChosenAuthRemote)
	}

	// Temporary restriction until a better solution is implemented
	// TODO: Allow for NTHash too?
	if cfg.RuntimeOptions.IsMethodEnabled("certservices") {
		if cfg.ChosenAuthRemote != "Password" {
			logFunc("🫠 [yellow]CertServices disabled (not supported for this auth method)[-]")
			cfg.RuntimeOptions.DisableMethod("certservices")
		}
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
			// Check if prompt_msgpack_overwrite is enabled
			if cfg.RuntimeOptions.GetPromptMsgpackOverwrite() {
				// Check if any msgpack files exist
				hasFiles, err := ingestMgr.checkMsgpackFilesExist()
				if err != nil {
					logFunc("🫠 [yellow]Warning: Failed to check for existing msgpack files: %v[-]", err)
				} else if hasFiles {
					// Show modal asking user if they want to overwrite
					uiApp.ShowYesNoModal(
						"Overwrite Existing Data?",
						"Existing msgpack files detected in the LDAP output folder.\nDo you want to overwrite them?",
						func() {
							// User chose Yes - proceed with ingestion
							// Reset ingested domains tracker for new run
							ingestMgr.processedDomains = &sync.Map{}

							// Mark initial domain as processed
							ingestMgr.processedDomains.Store(strings.ToUpper(initialDomain), true)

							ctx := context.Background()
							ingestMgr.start(ctx, initialDomain, initialBaseDN, initialDC)
						},
						func() {
							// User chose No - cancel ingestion
							logFunc("🛑 [yellow]Ingestion cancelled by user (existing files will not be overwritten)[-]")
						},
					)
					return
				}
			}

			// No prompt needed or no existing files - proceed with ingestion
			// Reset ingested domains tracker for new run
			ingestMgr.processedDomains = &sync.Map{}

			// Mark initial domain as processed
			ingestMgr.processedDomains.Store(strings.ToUpper(initialDomain), true)

			ctx := context.Background()
			ingestMgr.start(ctx, initialDomain, initialBaseDN, initialDC)
		}
	}

	if !disableRemote {
		remoteCollectionCallback = func() {
			// Check if prompt_msgpack_overwrite is enabled
			if cfg.RuntimeOptions.GetPromptMsgpackOverwrite() {
				// Check if any msgpack files exist
				hasFiles, err := remoteMgr.checkMsgpackFilesExist()
				if err != nil {
					logFunc("🫠 [yellow]Warning: Failed to check for existing msgpack files: %v[-]", err)
				} else if hasFiles {
					// Show modal asking user if they want to overwrite
					uiApp.ShowYesNoModal(
						"Overwrite Existing Data?",
						"Existing msgpack files detected in the remote collection output folder.\nDo you want to overwrite them?",
						func() {
							// User chose Yes - proceed with remote collection
							remoteMgr.start(uiApp)
						},
						func() {
							// User chose No - cancel remote collection
							logFunc("🛑 [yellow]Remote collection cancelled by user (existing files will not be overwritten)[-]")
						},
					)
					return
				}
			}

			// No prompt needed or no existing files - proceed with remote collection
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
			logFunc("✅ [green]Cache cleared from memory. RemoteCollect/Convert steps will reload it from disk.[-]")
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

// printVersion prints version information
func printVersion() {
	fmt.Printf("flashingestor %s\n", version)
}
