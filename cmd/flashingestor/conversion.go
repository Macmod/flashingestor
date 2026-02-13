package main

import (
	"fmt"
	"time"

	"github.com/Macmod/flashingestor/bloodhound"
	"github.com/Macmod/flashingestor/core"
	"github.com/Macmod/flashingestor/ui"
)

// ConversionManager handles BloodHound conversion.
type ConversionManager struct {
	bhInst *bloodhound.BH
	uiApp  *ui.Application
	logger *core.Logger
}

func newConversionManager(
	bhInst *bloodhound.BH,
	uiApp *ui.Application,
	logger *core.Logger,
) *ConversionManager {
	return &ConversionManager{
		bhInst: bhInst,
		uiApp:  uiApp,
		logger: logger,
	}
}

func (c *ConversionManager) start() {
	c.bhInst.ResetAbortFlag()
	c.uiApp.SetAbortCallback(func() {
		if c.bhInst.RequestAbort() {
			c.logger.Log0("🛑 [red]Abort requested for BloodHound conversion...[-]")
		}
	})

	c.logger.Log0("🔀 [cyan]Starting BloodHound conversion...[-]")

	// Set up conversion table and spinner
	c.uiApp.SetupConversionTable()

	// Create channel for conversion updates
	conversionUpdates := make(chan core.ConversionUpdate, 2000)
	c.bhInst.ConversionUpdates = conversionUpdates

	// Create spinner for conversion table
	spinner := ui.NewSingleTableSpinner(c.uiApp, c.uiApp.GetConversionTable(), 0)
	spinner.Start()

	// Start consumer goroutine for conversion updates
	go func() {
		for update := range conversionUpdates {
			c.handleConversionUpdate(c.uiApp, spinner, update)
		}
	}()

	go func() {
		c.uiApp.SetRunning(true, "conversion")

		defer func() {
			spinner.Stop()
			close(conversionUpdates)
			c.bhInst.ConversionUpdates = nil
			c.uiApp.SetAbortCallback(nil)
			c.uiApp.SetRunning(false, "")
		}()

		processStartTime := time.Now()
		c.bhInst.PerformConversion()
		processDuration := time.Since(processStartTime)

		if c.bhInst.IsAborted() {
			c.logger.Log0("🛑 [red]BloodHound conversion aborted after %s[-]", core.FormatDuration(processDuration))
		} else {
			c.logger.Log0("✅ [green]BloodHound conversion completed in %s[-]", core.FormatDuration(processDuration))

		}
		c.bhInst.ResetAbortFlag()
	}()
}

func (c *ConversionManager) handleConversionUpdate(uiApp *ui.Application, spinner *ui.Spinner, update core.ConversionUpdate) {
	row := update.Step

	switch update.Status {
	case "running":
		spinner.SetRunningRow(row)
		uiApp.UpdateConversionRow(row, "", "-", "-", "-", "-", "-", "-")
	case "done":
		spinner.SetDone(row)
		uiApp.UpdateConversionRow(row, "[green]✓ Done", "", "", "-", "", "-", update.Elapsed)
	case "aborted":
		spinner.SetDone(row)
		uiApp.UpdateConversionRow(row, "[red]× Aborted", "-", "-", "-", "-", "-", update.Elapsed)
	case "skipped":
		spinner.SetDone(row)
		uiApp.UpdateConversionRow(row, "[yellow]- Skipped", "-", "-", "-", "-", "-", "-")
	default:
		// Progress update - format values with colors
		var processedText, percentText string

		// Format Processed with colors
		if update.Processed == 0 {
			processedText = fmt.Sprintf("[yellow]%d/%d[-]", update.Processed, update.Total)
		} else if update.Processed == update.Total {
			processedText = fmt.Sprintf("[green]%d/%d[-]", update.Processed, update.Total)
		} else {
			processedText = fmt.Sprintf("[blue]%d/%d[-]", update.Processed, update.Total)
		}

		// Format Percent with colors
		if update.Percent >= 100.0 {
			percentText = fmt.Sprintf("[green]%.1f%%[-]", update.Percent)
		} else if update.Percent == 0.0 {
			percentText = fmt.Sprintf("[yellow]%.1f%%[-]", update.Percent)
		} else {
			percentText = fmt.Sprintf("[blue]%.1f%%[-]", update.Percent)
		}

		uiApp.UpdateConversionRow(row, "", processedText, percentText, update.Speed, update.AvgSpeed, update.ETA, update.Elapsed)
	}
}
