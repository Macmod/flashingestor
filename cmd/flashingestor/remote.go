package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Macmod/flashingestor/bloodhound"
	"github.com/Macmod/flashingestor/config"
	"github.com/Macmod/flashingestor/core"
	"github.com/Macmod/flashingestor/ui"
)

// RemoteCollectionManager handles remote data collection.
type RemoteCollectionManager struct {
	bhInst *bloodhound.BH
	auth   *config.CredentialMgr
	logger *core.Logger
}

func newRemoteCollectionManager(
	bhInst *bloodhound.BH,
	auth *config.CredentialMgr,
	logger *core.Logger,
) *RemoteCollectionManager {
	return &RemoteCollectionManager{
		bhInst: bhInst,
		auth:   auth,
		logger: logger,
	}
}

// checkMsgpackFilesExist checks if any .msgpack files exist in the remote folder
func (r *RemoteCollectionManager) checkMsgpackFilesExist() (bool, error) {
	remoteFolder := r.bhInst.ActiveFolder
	entries, err := os.ReadDir(remoteFolder)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".msgpack") {
			return true, nil
		}
	}

	return false, nil
}

func (r *RemoteCollectionManager) start(uiApp *ui.Application) {
	r.bhInst.ResetAbortFlag()
	uiApp.SetAbortCallback(func() {
		if r.bhInst.RequestAbort() {
			r.logger.Log0("🛑 [red]Abort requested for remote collection...[-]")
		}
	})

	r.logger.Log0("💻 [cyan]Starting remote collection...[-]")

	// Create remote collection updates channel
	remoteUpdates := make(chan core.RemoteCollectionUpdate, 1000)
	r.bhInst.RemoteCollectionUpdates = remoteUpdates

	// Setup UI table
	uiApp.SetupRemoteCollectionTable()

	// Start spinner for remote collection table
	spinner := ui.NewSingleTableSpinner(uiApp, uiApp.GetRemoteCollectTable(), 0)
	spinner.Start()

	// Start consumer for remote collection updates
	go r.handleRemoteCollectionUpdates(remoteUpdates, spinner, uiApp)

	go func() {
		uiApp.SetRunning(true, "remote")

		defer func() {
			close(remoteUpdates)
			spinner.Stop()
			uiApp.SetAbortCallback(nil)
			uiApp.SetRunning(false, "")
		}()

		processStartTime := time.Now()
		r.bhInst.PerformRemoteCollection(r.auth)
		processDuration := time.Since(processStartTime)

		if r.bhInst.IsAborted() {
			r.logger.Log0("🛑 [red]Remote collection aborted after %s. Results may be incomplete.[-]", core.FormatDuration(processDuration))
		} else {
			r.logger.Log0("✅ [green]Remote collection completed in %s[-]", core.FormatDuration(processDuration))
		}
	}()
}

func (r *RemoteCollectionManager) handleRemoteCollectionUpdates(updates <-chan core.RemoteCollectionUpdate, spinner *ui.Spinner, uiApp *ui.Application) {
	for update := range updates {
		// Handle status changes
		if update.Status == "running" {
			if spinner != nil {
				spinner.SetRunningRow(update.Step)
			}
			uiApp.UpdateRemoteCollectionRow(update.Step, "", "-", "-", "-", "-", "-", "-", "-")
		} else if update.Status == "done" {
			if spinner != nil {
				spinner.SetDone(update.Step)
			}
			uiApp.UpdateRemoteCollectionRow(update.Step, "[green]✓ Done", "", "", "-", "", "", "-", update.Elapsed)
		} else if update.Status == "aborted" {
			if spinner != nil {
				spinner.SetDone(update.Step)
			}
			uiApp.UpdateRemoteCollectionRow(update.Step, "[red]× Aborted", "", "", "-", "", "", "-", update.Elapsed)
		} else if update.Status == "skipped" {
			if spinner != nil {
				spinner.SetDone(update.Step)
			}
			uiApp.UpdateRemoteCollectionRow(update.Step, "[yellow]- Skipped", "-", "-", "-", "-", "-", "-", "-")
		} else {
			// Progress update - format with colors
			var processedText, percentText string

			// Color based on completion
			if update.Percent >= 100.0 || update.Processed == update.Total {
				processedText = fmt.Sprintf("[green]%d/%d[-]", update.Processed, update.Total)
				percentText = fmt.Sprintf("[green]%.1f%%[-]", update.Percent)
			} else if update.Percent == 0 || update.Processed == 0 {
				processedText = fmt.Sprintf("[yellow]%d/%d[-]", update.Processed, update.Total)
				percentText = fmt.Sprintf("[yellow]%.1f%%[-]", update.Percent)
			} else {
				processedText = fmt.Sprintf("[blue]%d/%d[-]", update.Processed, update.Total)
				percentText = fmt.Sprintf("[blue]%.1f%%[-]", update.Percent)
			}

			uiApp.UpdateRemoteCollectionRow(
				update.Step,
				"",
				processedText,
				percentText,
				update.Speed,
				update.AvgSpeed,
				update.Success,
				update.ETA,
				update.Elapsed,
			)
		}
	}
}
