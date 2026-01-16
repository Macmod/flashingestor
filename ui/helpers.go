package ui

import (
	"fmt"
	"time"

	"github.com/Macmod/flashingestor/config"
)

// padSpeed pads a speed string to 8 characters for consistent table width
func padSpeed(speed string) string {
	if len(speed) < 8 {
		return fmt.Sprintf("%-8s", speed)
	}
	return speed
}

// SwitchToPage switches between the progress tracker pages
func (app *Application) SwitchToPage(pageName string) {
	app.currentPage = pageName
	app.progressPages.SwitchToPage(pageName)

	// Update page selector to highlight active page
	switch pageName {
	case "ingest":
		app.pageSelector.SetText("[blue](1) Ingest[-]  (2) RemoteCollect  (3) Convert")
	case "remote":
		app.pageSelector.SetText("(1) Ingest  [blue](2) RemoteCollect[-]  (3) Convert")
	case "conversion":
		app.pageSelector.SetText("(1) Ingest  (2) RemoteCollect  [blue](3) Convert[-]")
	}
}

// UpdateLog adds a message to the log panel with timestamp
func (app *Application) UpdateLog(message string) {
	currentTime := time.Now()
	formattedTime := currentTime.Format("2006-01-02 15:04:05")

	go app.QueueUpdateDraw(func() {
		fmt.Fprintf(app.logPanel, "[white][%s][-] %s\n", formattedTime, message)
		app.logPanel.ScrollToEnd()
	})
}

// SetRuntimeOptions sets the runtime options reference for the UI
func (app *Application) SetRuntimeOptions(opts *config.RuntimeOptions) {
	app.runtimeOptions = opts
}
