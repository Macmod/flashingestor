package ui

import (
	"fmt"

	"github.com/rivo/tview"
)

// GetRemoteCollectTable returns the remote collection table
func (app *Application) GetRemoteCollectTable() *tview.Table {
	return app.remoteCollectPage
}

// SetupRemoteCollectionTable initializes the remote collection table
func (app *Application) SetupRemoteCollectionTable() {
	headers := []string{"Status", "Step", "Progress", "Percent", "Speed", "AvgSpeed", "Success", "ETA", "Elapsed"}
	for i, header := range headers {
		app.remoteCollectPage.SetCell(0, i, tview.NewTableCell(fmt.Sprintf("[blue]%s", header)).
			SetSelectable(false))
	}

	// Setup rows for each step
	app.remoteCollectPage.SetCell(1, 0, tview.NewTableCell("[yellow]Pending"))
	app.remoteCollectPage.SetCell(1, 1, tview.NewTableCell("Cache Load"))
	app.remoteCollectPage.SetCell(1, 2, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(1, 3, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(1, 4, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(1, 5, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(1, 6, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(1, 7, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(1, 8, tview.NewTableCell("-"))

	app.remoteCollectPage.SetCell(2, 0, tview.NewTableCell("[yellow]Pending"))
	app.remoteCollectPage.SetCell(2, 1, tview.NewTableCell("RemoteEnterpriseCAs"))
	app.remoteCollectPage.SetCell(2, 2, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(2, 3, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(2, 4, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(2, 5, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(2, 6, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(2, 7, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(2, 8, tview.NewTableCell("-"))

	app.remoteCollectPage.SetCell(3, 0, tview.NewTableCell("[yellow]Pending"))
	app.remoteCollectPage.SetCell(3, 1, tview.NewTableCell("DNS Lookups"))
	app.remoteCollectPage.SetCell(3, 2, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(3, 3, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(3, 4, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(3, 5, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(3, 6, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(3, 7, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(3, 8, tview.NewTableCell("-"))

	app.remoteCollectPage.SetCell(4, 0, tview.NewTableCell("[yellow]Pending"))
	app.remoteCollectPage.SetCell(4, 1, tview.NewTableCell("RemoteComputers"))
	app.remoteCollectPage.SetCell(4, 2, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(4, 3, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(4, 4, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(4, 5, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(4, 6, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(4, 7, tview.NewTableCell("-"))
	app.remoteCollectPage.SetCell(4, 8, tview.NewTableCell("-"))
}

// UpdateRemoteCollectionRow updates a specific step in the remote collection table
// row: 1=Cache Loading, 2=Remote Collection (CAs), 3=DNS Lookups, 4=Remote Collection (Computers)
// Columns: 0=Status, 1=Step, 2=Processed, 3=Percent, 4=Speed, 5=Avg Speed, 6=Success, 7=ETA, 8=Elapsed
func (app *Application) UpdateRemoteCollectionRow(row int, status, processed, percent, speed, avgSpeed, success, eta, elapsed string) {
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
		app.remoteCollectPage.SetCell(row, 4, tview.NewTableCell(speed))
	}
	if avgSpeed != "" {
		app.remoteCollectPage.SetCell(row, 5, tview.NewTableCell(avgSpeed))
	}
	if success != "" {
		app.remoteCollectPage.SetCell(row, 6, tview.NewTableCell(success))
	}
	if eta != "" {
		app.remoteCollectPage.SetCell(row, 7, tview.NewTableCell(eta))
	}
	if elapsed != "" {
		app.remoteCollectPage.SetCell(row, 8, tview.NewTableCell(elapsed))
	}
}
