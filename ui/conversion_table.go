package ui

import (
	"fmt"

	"github.com/rivo/tview"
)

// GetConversionTable returns the conversion table
func (app *Application) GetConversionTable() *tview.Table {
	return app.conversionPage
}

// SetupConversionTable initializes the conversion table
func (app *Application) SetupConversionTable() {
	app.conversionPage.Clear()

	headers := []string{"Status", "Step", "Progress", "Percent", "Speed", "AvgSpeed", "ETA", "Elapsed"}
	for i, header := range headers {
		app.conversionPage.SetCell(0, i, tview.NewTableCell(fmt.Sprintf("[blue]%s", header)).
			SetSelectable(false))
	}

	// Setup rows for each conversion step
	steps := []string{
		"Cache Load",
		"RemoteResults Load",
		"Schema",
		"Domain",
		"Configuration",
		"GroupPolicies",
		"OrganizationalUnits",
		"Containers",
		"Groups",
		"Computers",
		"Users",
	}

	// Add compression step only if compression is enabled
	if app.runtimeOptions != nil && app.runtimeOptions.GetCompressOutput() {
		steps = append(steps, "Compression")
	}

	for i, step := range steps {
		row := i + 1
		app.conversionPage.SetCell(row, 0, tview.NewTableCell("[yellow]Pending"))
		app.conversionPage.SetCell(row, 1, tview.NewTableCell(step))
		app.conversionPage.SetCell(row, 2, tview.NewTableCell("-"))
		app.conversionPage.SetCell(row, 3, tview.NewTableCell("-"))
		app.conversionPage.SetCell(row, 4, tview.NewTableCell("-"))
		app.conversionPage.SetCell(row, 5, tview.NewTableCell("-"))
		app.conversionPage.SetCell(row, 6, tview.NewTableCell("-"))
		app.conversionPage.SetCell(row, 7, tview.NewTableCell("-"))
	}
}

// UpdateConversionRow updates a specific step in the conversion table
// row: 1=Cache Loading, 2=Schema Loading, 3=Domain Processing, 4-9=Object conversions
// Columns: 0=Status, 1=Step, 2=Processed, 3=Percent, 4=Speed, 5=Avg Speed, 6=ETA, 7=Elapsed
func (app *Application) UpdateConversionRow(row int, status, processed, percent, speed, avgSpeed, eta, elapsed string) {
	// Called from background goroutines,
	// use QueueUpdate+RequestDraw for throttling
	app.QueueUpdate(func() {
		if status != "" {
			app.conversionPage.SetCell(row, 0, tview.NewTableCell(status))
		}
		if processed != "" {
			app.conversionPage.SetCell(row, 2, tview.NewTableCell(processed))
		}
		if percent != "" {
			app.conversionPage.SetCell(row, 3, tview.NewTableCell(percent))
		}
		if speed != "" {
			app.conversionPage.SetCell(row, 4, tview.NewTableCell(padString(speed, 8)))
		}
		if avgSpeed != "" {
			app.conversionPage.SetCell(row, 5, tview.NewTableCell(avgSpeed))
		}
		if eta != "" {
			app.conversionPage.SetCell(row, 6, tview.NewTableCell(eta))
		}
		if elapsed != "" {
			app.conversionPage.SetCell(row, 7, tview.NewTableCell(elapsed))
		}
		app.RequestDraw()
	})
}
