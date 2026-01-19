package ui

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// AddDomainTab creates a new tab for a domain's ingestion table
// Called from background goroutines (ingestDomain), must use QueueUpdateDraw
func (app *Application) AddDomainTab(domainName string) {
	// Check if domain already exists
	for _, domain := range app.activeDomains {
		if domain == domainName {
			return
		}
	}

	app.QueueUpdateDraw(func() {
		// Create new table for this domain
		domainTable := tview.NewTable()
		domainTable.SetBorder(false).
			SetBorderColor(tcell.ColorWhite)

		// Add to maps and lists
		app.ingestTables[domainName] = domainTable
		app.activeDomains = append(app.activeDomains, domainName)

		// Add page for this domain
		app.ingestPages.AddPage(domainName, domainTable, true, len(app.activeDomains) == 1)

		// Set as active if it's the first domain
		if len(app.activeDomains) == 1 {
			app.activeIngestDomain = domainName
		}

		// Update tab bar
		app.updateDomainTabBarLocked()
	})
}

// GetDomainTable returns the table for a specific domain
func (app *Application) GetDomainTable(domainName string) *tview.Table {
	return app.ingestTables[domainName]
}

// updateDomainTabBarLocked updates the tab bar display with all active domains
// MUST be called from within QueueUpdate/QueueUpdateDraw or from main goroutine only
func (app *Application) updateDomainTabBarLocked() {
	if len(app.activeDomains) == 0 {
		app.ingestTabBar.SetText("")
		return
	}

	var tabText string
	for i, domain := range app.activeDomains {
		if domain == app.activeIngestDomain {
			tabText += fmt.Sprintf("[black:blue] %s [-:-]", domain)
		} else {
			tabText += fmt.Sprintf(" [white]%s[-] ", domain)
		}
		if i < len(app.activeDomains)-1 {
			tabText += "│"
		}
	}
	app.ingestTabBar.SetText(tabText)
}

// SwitchToDomainTab switches to a specific domain's ingestion table
// Called from background goroutines (ingestDomain), must use QueueUpdateDraw
func (app *Application) SwitchToDomainTab(domainName string) {
	// Check if domain exists
	found := false
	for _, domain := range app.activeDomains {
		if domain == domainName {
			found = true
			break
		}
	}
	if !found {
		return
	}

	app.QueueUpdateDraw(func() {
		app.activeIngestDomain = domainName
		app.ingestPages.SwitchToPage(domainName)
		app.updateDomainTabBarLocked()
	})
}

// SwitchToNextDomainTab cycles to the next domain tab
// Called from keyboard input handlers (main goroutine), can directly modify UI
func (app *Application) SwitchToNextDomainTab() {
	if len(app.activeDomains) == 0 {
		return
	}

	// Find current domain index
	currentIndex := 0
	for i, domain := range app.activeDomains {
		if domain == app.activeIngestDomain {
			currentIndex = i
			break
		}
	}

	// Switch to next domain (wrap around)
	nextIndex := (currentIndex + 1) % len(app.activeDomains)
	nextDomain := app.activeDomains[nextIndex]
	
	// Since this is called from input handler (main goroutine), directly modify UI
	app.activeIngestDomain = nextDomain
	app.ingestPages.SwitchToPage(nextDomain)
	app.updateDomainTabBarLocked()
}

// handleTabClick processes mouse clicks on the domain tab bar
func (app *Application) handleTabClick(x int) {
	if len(app.activeDomains) == 0 {
		return
	}

	// Parse the tab bar text to find which domain was clicked
	// Tab format: " DOMAIN " or "[black:blue] DOMAIN [-:-]" with " │" separator
	// Each tab is approximately: domain_length + padding (spaces) + separator (3 chars for " │")

	currentX := 0
	for i, domain := range app.activeDomains {
		// Calculate approximate tab width
		// Active tab: "[black:blue] " (14 chars) + domain + " [-:-]" (6 chars) = 20 + len(domain)
		// Inactive tab: " [white]" (8 chars) + domain + "[-] " (5 chars) = 13 + len(domain)
		var tabWidth int
		if domain == app.activeIngestDomain {
			tabWidth = len(domain) + 2 // Account for spaces around domain name
		} else {
			tabWidth = len(domain) + 2
		}

		// Add separator width if not last tab
		if i < len(app.activeDomains)-1 {
			tabWidth += 3 // " │"
		}

		// Check if click is within this tab's bounds
		if x >= currentX && x < currentX+tabWidth {
			// Called from mouse handler (main goroutine), directly modify UI
			app.activeIngestDomain = domain
			app.ingestPages.SwitchToPage(domain)
			app.updateDomainTabBarLocked()
			return
		}

		currentX += tabWidth
	}
}
