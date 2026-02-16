package ui

import (
	"fmt"

	"github.com/rivo/tview"
)

// InsertIngestHeader initializes a row in the ingestion table for a specific domain
// Called from goroutine in ingestDomain
func (app *Application) InsertIngestHeader(domainName string) {
	table, ok := app.ingestTables[domainName]
	if !ok {
		return
	}

	app.QueueUpdateDraw(func() {
		headers := []string{"Status", "Query", "Searches", "Entries", "Speed", "AvgSpeed", "Elapsed"}
		for i, header := range headers {
			table.SetCell(0, i, tview.NewTableCell(fmt.Sprintf("[blue]%s", header)).
				SetSelectable(false))
		}
	})
}

// SetupIngestRow initializes a row in the ingestion table for a specific domain
// Called from goroutine in ingestDomain
func (app *Application) SetupIngestRow(domainName string, row int, jobName string) {
	table, ok := app.ingestTables[domainName]
	if !ok {
		return
	}

	app.QueueUpdateDraw(func() {
		table.SetCell(row, 0, tview.NewTableCell("[yellow]~ Pending"))
		table.SetCell(row, 1, tview.NewTableCell(jobName))
		table.SetCell(row, 2, tview.NewTableCell("0"))
		table.SetCell(row, 3, tview.NewTableCell("0"))
		table.SetCell(row, 4, tview.NewTableCell("0.0"))
		table.SetCell(row, 5, tview.NewTableCell("0.0"))
		table.SetCell(row, 6, tview.NewTableCell("-"))
	})
}

// UpdateIngestRow updates a specific row in the ingestion table for a specific domain
func (app *Application) UpdateIngestRow(domainName string, row int, status, requests, entries, speed, avgSpeed, elapsed string) {
	table, ok := app.ingestTables[domainName]
	if !ok {
		return
	}

	// Called from background goroutines very frequently,
	// use QueueUpdate+RequestDraw for throttling
	app.QueueUpdate(func() {
		if status != "" {
			table.SetCell(row, 0, tview.NewTableCell(status))
		}
		if requests != "" {
			table.SetCell(row, 2, tview.NewTableCell(requests))
		}
		if entries != "" {
			table.SetCell(row, 3, tview.NewTableCell(entries))
		}
		if speed != "" {
			table.SetCell(row, 4, tview.NewTableCell(padString(speed, 8)))
		}
		if avgSpeed != "" {
			table.SetCell(row, 5, tview.NewTableCell(avgSpeed))
		}
		if elapsed != "" {
			table.SetCell(row, 6, tview.NewTableCell(elapsed))
		}
		app.RequestDraw()
	})
}
