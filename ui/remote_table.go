package ui

import (
	"fmt"

	"github.com/Macmod/flashingestor/config"
	"github.com/rivo/tview"
)

// GetRemoteCollectTable returns the remote collection table
func (app *Application) GetRemoteCollectTable() *tview.Table {
	return app.remoteCollectPage
}

// SetupRemoteCollectionTable initializes the remote collection table
func (app *Application) SetupRemoteCollectionTable(runtimeOptions *config.RuntimeOptions) {
	// Set headers
	headers := []string{"Status", "Step", "Progress", "Percent", "Speed", "AvgSpeed", "Success", "ETA", "Elapsed"}
	for i, header := range headers {
		app.remoteCollectPage.SetCell(0, i, tview.NewTableCell(fmt.Sprintf("[blue]%s", header)).
			SetSelectable(false))
	}

	// Define steps in order: Cache -> GPOLocalGroups (optional) -> RemoteEnterpriseCAs (optional) -> Computer steps (optional)
	steps := []string{"Cache Load"}

	if runtimeOptions != nil && runtimeOptions.IsMethodEnabled("gpolocalgroup") {
		steps = append(steps, "GPOLocalGroups")
	}

	if runtimeOptions != nil && runtimeOptions.IsAnyCAMethodEnabled() {
		steps = append(steps, "RemoteEnterpriseCAs")
	}

	// Add computer collection steps if any computer methods are enabled
	if runtimeOptions != nil && runtimeOptions.IsAnyComputerMethodEnabled() {
		steps = append(steps, []string{
			"Load Computers",
			"Status Checks",
			"RemoteComputers",
		}...)
	}

	// Setup rows for each step
	for row, stepName := range steps {
		rowNum := row + 1 // Row 0 is headers
		app.remoteCollectPage.SetCell(rowNum, 0, tview.NewTableCell("[yellow]Pending"))
		app.remoteCollectPage.SetCell(rowNum, 1, tview.NewTableCell(stepName))
		for col := 2; col < len(headers); col++ {
			app.remoteCollectPage.SetCell(rowNum, col, tview.NewTableCell("-"))
		}
	}
}

// UpdateRemoteCollectionRow updates a specific step in the remote collection table
// Steps are dynamically numbered based on enabled methods:
// - Always: Cache Load, Load Computers, Status Checks, RemoteComputers
// - Conditional: GPOLocalGroups (step 2 if enabled), RemoteEnterpriseCAs (before RemoteComputers if CA methods enabled)
// Columns: 0=Status, 1=Step, 2=Processed, 3=Percent, 4=Speed, 5=Avg Speed, 6=Success, 7=ETA, 8=Elapsed
func (app *Application) UpdateRemoteCollectionRow(row int, status, processed, percent, speed, avgSpeed, success, eta, elapsed string) {
	// Called from background goroutines, use QueueUpdate to modify cells
	// then RequestDraw for throttled screen updates
	app.QueueUpdate(func() {
		if status != "" {
			app.remoteCollectPage.SetCell(row, 0, tview.NewTableCell(status))
		}
		if processed != "" {
			app.remoteCollectPage.SetCell(row, 2, tview.NewTableCell(processed))
		}
		if percent != "" {
			app.remoteCollectPage.SetCell(row, 3, tview.NewTableCell(percent))
		}
		if speed != "" {
			app.remoteCollectPage.SetCell(row, 4, tview.NewTableCell(padString(speed, 8)))
		}
		if avgSpeed != "" {
			app.remoteCollectPage.SetCell(row, 5, tview.NewTableCell(avgSpeed))
		}
		if success != "" {
			app.remoteCollectPage.SetCell(row, 6, tview.NewTableCell(success))
		}
		if eta != "" {
			app.remoteCollectPage.SetCell(row, 7, tview.NewTableCell(padString(eta, 5)))
		}
		if elapsed != "" {
			app.remoteCollectPage.SetCell(row, 8, tview.NewTableCell(elapsed))
		}
		app.RequestDraw()
	})
}
