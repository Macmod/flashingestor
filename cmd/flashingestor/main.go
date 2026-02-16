package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
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
	version = "0.3.2"
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

	logChannel := make(chan core.LogMessage, 1000)

	var logFile *os.File
	if cfg.LogFile != "" {
		logFile, err = core.OpenLogFile(cfg.LogFile)
		if err != nil {
			log.Fatal("Failed to open log file:", err)
		}
		defer logFile.Close()
	}

	logger := core.NewLogger(logChannel, logFile, uiApp.UpdateLog, cfg.VerbosityLevel)
	go logger.Start()

	logger.Log0("🧩 Welcome to FlashIngestor %s", version)

	// Start pprof HTTP server for profiling if enabled
	if cfg.PprofEnabled {
		go func() {
			if err := http.ListenAndServe("localhost:6060", nil); err != nil {
				logger.Log0("❌ [red]Pprof server error:[-] %v", err)
			}
		}()
	}
	if cfg.PprofEnabled {
		logger.Log0("🔬 [blue]Pprof profiling enabled:[-] http://localhost:6060/debug/pprof/")
	}
	logger.Log0("⭕ [blue]Config file[-]: " + cfg.ConfigPath)
	logger.Log0("⭕ [blue]Output folder[-]: " + cfg.OutputDir)
	logger.Log0("⭕ [blue]Verbosity[-]: " + core.VerbosityString(cfg.VerbosityLevel))

	resolver := cfg.Resolver
	customDNS := cfg.CustomDns
	if customDNS != "" {
		if cfg.DnsTcp {
			logger.Log0("🔍 [blue]DNS protocol[-]: TCP")
		} else {
			logger.Log0("🔍 [blue]DNS protocol[-]: UDP")
		}

		logger.Log0("🔍 [blue]Custom DNS resolver[-]: \"" + customDNS + "\"")
	} else {
		logger.Log0("🔍 [blue]Using system DNS resolver: consider specifying a DNS server explicitly.[-]")
	}

	logger.Log0("⭕ [blue]LDAP scheme[-]: " + cfg.LdapAuthOptions.Scheme)

	// Log LDAP obfuscation settings
	if cfg.LdapxFilter != "" || cfg.LdapxAttrs != "" || cfg.LdapxBaseDN != "" {
		logger.Log0("🎭 [blue]LDAP obfuscation (ldapx) enabled:[-]")
		if cfg.LdapxFilter != "" {
			logger.Log0("   [blue]Filter chain[-]: %s", cfg.LdapxFilter)
		}
		if cfg.LdapxAttrs != "" {
			logger.Log0("   [blue]Attrs chain[-]: %s", cfg.LdapxAttrs)
		}
		if cfg.LdapxBaseDN != "" {
			logger.Log0("   [blue]BaseDN chain[-]: %s", cfg.LdapxBaseDN)
		}
	}

	bhInst := &bloodhound.BH{}
	bhInst.Init(
		dirs.LDAP, dirs.Remote, dirs.BloodHound, resolver,
		cfg.RemoteWorkers,
		cfg.RemoteComputerTimeout, cfg.RemoteMethodTimeout,
		cfg.RuntimeOptions, logger,
	)

	// Use RemoteAuthOptions for remote collection, fallback to StandardAuthOptions if not set
	if cfg.ChosenAuthIngest == "" {
		logger.Log0("🔗 [blue]Auth method (ingestion)[-]: None")
	} else {
		// Auto-enable SimpleBind for anonymous authentication
		if cfg.ChosenAuthIngest == "Anonymous" {
			cfg.LdapAuthOptions.SimpleBind = true
		}

		authMethodIngestStr := cfg.ChosenAuthIngest

		// For ingestion, SimpleBind takes precedence over all methods
		if cfg.LdapAuthOptions.SimpleBind {
			authMethodIngestStr += " [blue](SimpleBind)[-]"
		} else if cfg.IngestAuth.Kerberos() {
			// Certificate with Kerberos uses PKINIT
			// other credential types (password, NTHash, CCacche, AES Key) used with -k
			// should just be labeled "Kerberos"
			if cfg.ChosenAuthIngest == "CertPFX" || cfg.ChosenAuthIngest == "CertPEM" {
				authMethodIngestStr += " [blue](PKINIT/Kerberos)[-]"
			} else {
				authMethodIngestStr += " [blue](Kerberos)[-]"
			}
		} else if cfg.ChosenAuthIngest == "CertPFX" || cfg.ChosenAuthIngest == "CertPEM" {
			// Certificate without Kerberos can be said to use SChannel
			authMethodIngestStr += " [blue](SChannel)[-]"
		} else {
			// Otherwise, Password/NTHash uses NTLM
			authMethodIngestStr += " [blue](NTLM)[-]"
		}

		logger.Log0("🔗 [blue]Auth method (ingestion)[-]: " + authMethodIngestStr)
	}

	if cfg.ChosenAuthRemote == "Anonymous" {
		// Temporarily disabled until I can decide
		cfg.ChosenAuthRemote = ""
	}

	if cfg.ChosenAuthRemote == "" {
		logger.Log0("🔗 [blue]Auth method (remote collection)[-]: None")
	} else {
		authMethodRemoteStr := cfg.ChosenAuthRemote
		if cfg.ChosenAuthRemote == "CertPFX" || cfg.ChosenAuthRemote == "CertPEM" {
			// Certificates for remote collection always use PKINIT
			authMethodRemoteStr += " [blue](PKINIT/Kerberos)[-]"
		} else if cfg.RemoteAuth.Kerberos() {
			// Kerberos Ticket / AESKey
			authMethodRemoteStr += " [blue](Kerberos)[-]"
		} else {
			// Password / NTHash uses NTLM
			authMethodRemoteStr += " [blue](NTLM)[-]"
		}

		logger.Log0("🔗 [blue]Auth method (remote collection)[-]: " + authMethodRemoteStr)
	}

	// Check if we have proper authentication credentials
	// to determine whether to disable methods
	disableIngest := false
	if cfg.ChosenAuthIngest == "" {
		disableIngest = true
		logger.Log0("🫠 [red]No authentication credentials detected for ingestion. Ingestion will be disabled for this session.[-]")
	}

	disableRemote := cfg.ChosenAuthRemote == ""
	if disableRemote {
		logger.Log0("🫠 [red]No authentication credentials detected for remote collection. Remote collection will be disabled for this session.[-]")
	}

	// Check if we should disable recurse_trusts and search_forest
	// when using an auth method that doesn't support cross-domain authentication
	ingestNoCrossDomain := !slices.Contains([]string{"Password", "NTHash", "Anonymous"}, cfg.ChosenAuthIngest) || cfg.IngestAuth.Kerberos() || (cfg.LdapAuthOptions.SimpleBind && cfg.ChosenAuthIngest != "Anonymous")

	if cfg.RuntimeOptions.GetRecurseTrusts() && ingestNoCrossDomain {
		logger.Log0("🫠 [yellow]RecurseTrusts disabled (not supported for this auth method)[-]")
		cfg.RuntimeOptions.SetRecurseTrusts(false)
	}

	if cfg.RuntimeOptions.GetSearchForest() && ingestNoCrossDomain {
		logger.Log0("🫠 [yellow]SearchForest disabled (not supported for this auth method)[-]")
		cfg.RuntimeOptions.SetSearchForest(false)
	}

	initialDomainRemote := strings.ToUpper(cfg.RemoteAuth.Creds().Domain)
	remoteNoCrossDomain := initialDomainRemote != "." && (!slices.Contains([]string{"Password", "NTHash"}, cfg.ChosenAuthRemote) || cfg.RemoteAuth.Kerberos())
	if remoteNoCrossDomain {
		logger.Log0("🫠 [yellow]Remote collection methods will be limited to domain '" + initialDomainRemote + "' (cross-domain authentication not supported for this auth method)[-]")
	}

	// Temporary restriction until a better solution is implemented
	// TODO: Allow for NTHash too?
	if cfg.RuntimeOptions.IsMethodEnabled("certservices") {
		if cfg.ChosenAuthRemote != "Password" {
			logger.Log0("🫠 [yellow]CertServices disabled (not supported for this auth method)[-]")
			cfg.RuntimeOptions.DisableMethod("certservices")
		}
	}

	ingestMgr := IngestionManager{
		jobManager:          jobManager,
		ldapAuthOptions:     cfg.LdapAuthOptions,
		auth:                cfg.IngestAuth,
		resolver:            resolver,
		queryDefs:           cfg.RuntimeOptions.GetQueries(),
		ldapFolder:          dirs.LDAP,
		logger:              logger,
		uiApp:               uiApp,
		processedDomains:    &sync.Map{},
		includeACLs:         cfg.RuntimeOptions.GetIncludeACLs(),
		recurseTrusts:       cfg.RuntimeOptions.GetRecurseTrusts(),
		recurseFeasibleOnly: cfg.RuntimeOptions.GetRecurseFeasibleOnly(),
		searchForest:        cfg.RuntimeOptions.GetSearchForest(),
		ldapsToLdapFallback: cfg.RuntimeOptions.GetLdapsToLdapFallback(),
		appendForestDomains: cfg.RuntimeOptions.GetAppendForestDomains(),
		ldapxFilter:         cfg.LdapxFilter,
		ldapxAttrs:          cfg.LdapxAttrs,
		ldapxBaseDN:         cfg.LdapxBaseDN,
	}

	conversionMgr := newConversionManager(bhInst, uiApp, logger)

	remoteMgr := newRemoteCollectionManager(
		bhInst,
		uiApp,
		logger,
	)

	var initialDomain, initialBaseDN, initialDC string
	if !disableIngest {
		initialDomain = strings.ToUpper(cfg.IngestAuth.Creds().Domain)
		if initialDomain == "" {
			logger.Log0("❌ [red]Failed to determine initial domain for ingestion from the credentials. Check your credentials and try again.\n")
		} else {
			logger.Log0("🔗 [blue]Initial domain[-]: \"%s\"", initialDomain)

			initialBaseDN = "DC=" + strings.ReplaceAll(initialDomain, ".", ",DC=")
			logger.Log0("🔗 [blue]Inferred BaseDN[-]: \"%s\"", initialBaseDN)

			initialDC = cfg.DomainController
			if initialDC == "" {
				logger.Log0("🔗 [blue]Initial DC[-]: (auto-discovered)")
			} else {
				logger.Log0("🔗 [blue]Initial DC[-]: \"%s\"", initialDC)
			}
		}
	}
	logger.Log0("-")

	var ingestionCallback, remoteCollectionCallback func()

	if !disableIngest {
		ingestionCallback = func() {
			// Check if prompt_msgpack_overwrite is enabled
			if cfg.RuntimeOptions.GetPromptMsgpackOverwrite() {
				// Check if any msgpack files exist
				hasFiles, err := ingestMgr.checkMsgpackFilesExist()
				if err != nil {
					logger.Log0("🫠 [yellow]Warning: Failed to check for existing msgpack files: %v[-]", err)
				} else if hasFiles {
					// Show modal asking user if they want to overwrite
					uiApp.ShowYesNoModal(
						"Overwrite Existing Data?",
						"Existing msgpack files detected in the LDAP output folder.\nDo you want to overwrite them?",
						func() {
							// User chose Yes - proceed with ingestion
							// Reset ingested domains tracker for new run
							ingestMgr.processedDomains.Range(func(key, value interface{}) bool {
								ingestMgr.processedDomains.Delete(key)
								return true
							})

							// Mark initial domain as processed
							ingestMgr.processedDomains.Store(strings.ToUpper(initialDomain), true)

							ctx := context.Background()
							ingestMgr.start(ctx, initialDomain, initialBaseDN, initialDC)
						},
						func() {
							// User chose No - cancel ingestion
							logger.Log0("🛑 [yellow]Ingestion cancelled by user (existing files will not be overwritten)[-]")
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
					logger.Log0("🫠 [yellow]Warning: Failed to check for existing msgpack files: %v[-]", err)
				} else if hasFiles {
					// Show modal asking user if they want to overwrite
					uiApp.ShowYesNoModal(
						"Overwrite Existing Data?",
						"Existing msgpack files detected in the remote collection output folder.\nDo you want to overwrite them?",
						func() {
							// User chose Yes - proceed with remote collection
							remoteMgr.start(cfg.RemoteAuth, remoteNoCrossDomain)
						},
						func() {
							// User chose No - cancel remote collection
							logger.Log0("🛑 [yellow]Remote collection cancelled by user (existing files will not be overwritten)[-]")
						},
					)
					return
				}
			}

			// No prompt needed or no existing files - proceed with remote collection
			remoteMgr.start(cfg.RemoteAuth, remoteNoCrossDomain)
		}
	}

	uiApp.SetButtonCallbacks(
		ingestionCallback,
		conversionMgr.start,
		remoteCollectionCallback,
		func() {
			// Clear cache callback
			builder.BState().Clear()
			logger.Log0("✅ [green]Cache cleared from memory. RemoteCollect/Convert steps will reload it from disk.[-]")
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
