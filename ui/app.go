// Package ui implements the terminal user interface (TUI) for flashingestor
// using tview, providing interactive progress tracking and control.
package ui

import (
	"sync/atomic"
	"time"

	"github.com/Macmod/flashingestor/config"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// Application wraps the tview application for better organization
type Application struct {
	*tview.Application
	logPanel           *tview.TextView
	ingestTables       map[string]*tview.Table // Per-domain ingestion tables
	ingestPages        *tview.Pages            // Pages for domain-specific ingestion tables
	ingestTabBar       *tview.TextView         // Tab bar for domain selection
	activeDomains      []string                // List of active domain tabs
	activeIngestDomain string                  // Currently selected domain for ingestion view
	remoteCollectPage  *tview.Table
	conversionPage     *tview.Table
	progressPages      *tview.Pages
	progressTracker    *tview.Flex // Store reference to progress tracker
	pageSelector       *tview.TextView
	startIngButton     *tview.Button
	startConvButton    *tview.Button
	startRemoteButton  *tview.Button
	abortButton        *tview.Button
	buttonPanel        *tview.Flex
	statusPanel        *tview.Flex
	rootFlex           *tview.Flex  // Store reference to root flex
	mainPages          *tview.Pages // Pages for modal overlays
	isRunning          bool         // Track if any operation is currently running
	currentPage        string
	abortCallback      func() // Callback to abort current operation
	ingestionCb        func() // Store callbacks for keybindings
	conversionCb       func()
	remoteCollectionCb func()
	clearCacheCb       func()
	runtimeOptions     *config.RuntimeOptions // Runtime configuration options

	// Throttled update mechanism
	pendingUpdate  atomic.Bool   // Whether a UI update is pending
	updateTicker   *time.Ticker  // Ticker for throttling updates
	updateStopChan chan struct{} // Channel to stop the update goroutine
}

// NewApplication creates a new UI application instance
func NewApplication() *Application {
	app := &Application{
		Application:    tview.NewApplication(),
		ingestTables:   make(map[string]*tview.Table),
		activeDomains:  make([]string, 0),
		updateTicker:   time.NewTicker(300 * time.Millisecond),
		updateStopChan: make(chan struct{}),
	}
	app.setupUI()
	app.startThrottledUpdates()
	return app
}

// setupUI initializes all UI components
func (app *Application) setupUI() {
	// Set global border style to single line with blue when focused
	tview.Borders.HorizontalFocus = tview.Borders.Horizontal
	tview.Borders.VerticalFocus = tview.Borders.Vertical
	tview.Borders.TopLeftFocus = tview.Borders.TopLeft
	tview.Borders.TopRightFocus = tview.Borders.TopRight
	tview.Borders.BottomLeftFocus = tview.Borders.BottomLeft
	tview.Borders.BottomRightFocus = tview.Borders.BottomRight

	// Set global theme colors
	tview.Styles.PrimitiveBackgroundColor = tcell.ColorDefault
	tview.Styles.ContrastBackgroundColor = tcell.ColorDefault
	tview.Styles.PrimaryTextColor = tcell.ColorWhite
	tview.Styles.BorderColor = tcell.ColorWhite
	tview.Styles.TitleColor = tcell.ColorWhite
	tview.Styles.GraphicsColor = tcell.ColorWhite

	app.logPanel = tview.NewTextView()
	app.logPanel.SetDynamicColors(true).
		SetWordWrap(false).
		SetTitle("Execution Log").
		SetBorder(true).
		SetBorderColor(tcell.ColorWhite)

	// Create tab bar for domain-specific ingestion tables
	app.ingestTabBar = tview.NewTextView()
	app.ingestTabBar.SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)

	// Add mouse click handler for domain tab switching
	app.ingestTabBar.SetMouseCapture(func(action tview.MouseAction, event *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
		if action == tview.MouseLeftClick {
			x, _ := event.Position()
			app.handleTabClick(x)
		}
		return action, event
	})

	// Create pages for domain-specific ingestion tables
	app.ingestPages = tview.NewPages()

	// Combine tab bar and pages in a flex container for ingestion
	ingestPage := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(app.ingestTabBar, 1, 0, false).
		AddItem(app.ingestPages, 0, 1, true)

	// Create tables for each operation type
	app.remoteCollectPage = tview.NewTable()
	app.conversionPage = tview.NewTable()

	// Create pages for the progress tracker
	app.progressPages = tview.NewPages().
		AddPage("ingest", ingestPage, true, true).
		AddPage("remote", app.remoteCollectPage, true, false).
		AddPage("conversion", app.conversionPage, true, false)
	app.progressPages.SetBorder(true).SetBorderColor(tcell.ColorWhite)
	app.progressPages.
		SetFocusFunc(func() {
			app.progressPages.SetBorderColor(tcell.ColorBlue)
			app.progressPages.SetTitleColor(tcell.ColorBlue)
		}).
		SetBlurFunc(func() {
			app.progressPages.SetBorderColor(tcell.ColorWhite)
			app.progressPages.SetTitleColor(tcell.ColorWhite)
		})

	app.currentPage = "ingest"

	// Create page selector
	app.pageSelector = tview.NewTextView()
	app.pageSelector.SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter).
		SetText("[blue](1) Ingest[-]  (2) RemoteCollect  (3) Convert")

	// Combine page selector and pages in a flex container
	app.progressTracker = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(app.pageSelector, 1, 0, false).
		AddItem(app.progressPages, 0, 1, true)

	// Create control buttons
	app.startIngButton = tview.NewButton("Ingest (C-l)").
		SetStyle(tcell.StyleDefault.Background(tcell.ColorBlue).Foreground(tcell.ColorBlack)).
		SetActivatedStyle(tcell.StyleDefault.Background(tcell.ColorWhite).Foreground(tcell.ColorBlue))

	app.startConvButton = tview.NewButton("Convert (C-s)").
		SetStyle(tcell.StyleDefault.Background(tcell.ColorBlue).Foreground(tcell.ColorBlack)).
		SetActivatedStyle(tcell.StyleDefault.Background(tcell.ColorWhite).Foreground(tcell.ColorBlue))

	app.startRemoteButton = tview.NewButton("Remote (C-r)").
		SetStyle(tcell.StyleDefault.Background(tcell.ColorBlue).Foreground(tcell.ColorBlack)).
		SetActivatedStyle(tcell.StyleDefault.Background(tcell.ColorWhite).Foreground(tcell.ColorBlue))

	clearCacheButton := tview.NewButton("ClearCache (C-k)").
		SetStyle(tcell.StyleDefault.Background(tcell.ColorDarkCyan).Foreground(tcell.ColorBlack)).
		SetActivatedStyle(tcell.StyleDefault.Background(tcell.ColorWhite).Foreground(tcell.ColorDarkCyan))
	clearCacheButton.SetSelectedFunc(func() {
		if app.clearCacheCb != nil {
			app.clearCacheCb()
		}
	})

	app.abortButton = tview.NewButton("Abort (C-a)").
		SetStyle(tcell.StyleDefault.Background(tcell.ColorRed).Foreground(tcell.ColorWhite)).
		SetActivatedStyle(tcell.StyleDefault.Background(tcell.ColorWhite).Foreground(tcell.ColorRed))
	app.abortButton.SetSelectedFunc(func() {
		if app.abortCallback != nil {
			app.abortCallback()
		}
	})

	// Create button panel
	app.buttonPanel = tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(app.startIngButton, 14, 0, false).
		AddItem(tview.NewBox(), 1, 0, false). // Spacer
		AddItem(app.startRemoteButton, 14, 0, false).
		AddItem(tview.NewBox(), 1, 0, false). // Spacer
		AddItem(app.startConvButton, 15, 0, false).
		AddItem(tview.NewBox(), 1, 0, false). // Spacer
		AddItem(clearCacheButton, 18, 0, false)

	// Create status panel (hidden initially)
	app.statusPanel = tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(tview.NewTextView().SetText("Operation in progress...").SetDynamicColors(true), 0, 1, false).
		AddItem(app.abortButton, 13, 0, false).
		AddItem(tview.NewBox(), 1, 0, false)
	/*
		app.statusPanel.
			SetFocusFunc(func() {
				app.statusPanel.SetBorderColor(tcell.ColorBlue)
				app.statusPanel.SetTitleColor(tcell.ColorBlue)
			}).
			SetBlurFunc(func() {
				app.statusPanel.SetBorderColor(tcell.ColorWhite)
				app.statusPanel.SetTitleColor(tcell.ColorWhite)
			})
	*/

	app.buttonPanel.SetBorder(true).SetBorderColor(tcell.ColorWhite)
	/*
		app.buttonPanel.
			SetFocusFunc(func() {
				app.buttonPanel.SetBorderColor(tcell.ColorBlue)
				app.buttonPanel.SetTitleColor(tcell.ColorBlue)
			}).
			SetBlurFunc(func() {
				app.buttonPanel.SetBorderColor(tcell.ColorWhite)
				app.buttonPanel.SetTitleColor(tcell.ColorWhite)
			})
	*/

	// Main layout with buttons at the top
	appFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(app.buttonPanel, 3, 0, false).
		AddItem(app.progressTracker, 15, 0, false).
		AddItem(app.logPanel, 0, 1, false)

	appFlex.SetTitle("FlashIngestor").
		SetBorder(true).
		SetBorderColor(tcell.ColorWhite)

	app.rootFlex = appFlex

	// Create pages container for modal overlays
	app.mainPages = tview.NewPages()
	app.mainPages.AddPage("main", app.rootFlex, true, true)

	// Set up keyboard shortcuts for page switching and domain tab switching
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		/*
			// Handle Ctrl+O for options panel
			if event.Key() == tcell.KeyCtrlO {
				if app.mainPages.HasPage("options") {
					app.mainPages.RemovePage("options")
				} else if app.runtimeOptions != nil {
					app.ShowOptionsPanel(app.runtimeOptions)
				}
				return nil
			}
		*/
		// Handle Ctrl+L, Ctrl+R, Ctrl+S for button actions
		if event.Key() == tcell.KeyCtrlL {
			if !app.isRunning && app.ingestionCb != nil {
				app.showConfirmModal("Start LDAP Ingestion?", "This will begin collecting data from the LDAP server.", app.ingestionCb)
			}
			return nil
		}
		if event.Key() == tcell.KeyCtrlR {
			if !app.isRunning && app.remoteCollectionCb != nil {
				app.showConfirmModal("Start Remote Collection?", "This will perform active collection on ALL discovered computers. Continue?", app.remoteCollectionCb)
			}
			return nil
		}
		if event.Key() == tcell.KeyCtrlS {
			if !app.isRunning && app.conversionCb != nil {
				// Convert doesn't need confirmation
				app.conversionCb()
			}
			return nil
		}
		if event.Key() == tcell.KeyCtrlK {
			if !app.isRunning && app.clearCacheCb != nil {
				app.clearCacheCb()
			}
			return nil
		}
		if event.Key() == tcell.KeyCtrlA {
			if app.isRunning && app.abortCallback != nil {
				app.abortCallback()
			}
			return nil
		}

		switch event.Rune() {
		case '1':
			app.SwitchToPage("ingest")
			return nil
		case '2':
			app.SwitchToPage("remote")
			return nil
		case '3':
			app.SwitchToPage("conversion")
			return nil
		}

		// Handle Tab key for switching between domain tabs (only when on ingest page)
		if event.Key() == tcell.KeyTab && app.currentPage == "ingest" && len(app.activeDomains) > 0 {
			app.SwitchToNextDomainTab()
			return nil
		}
		return event
	})

	app.rootFlex = appFlex
	app.SetRoot(app.mainPages, true).EnableMouse(true)
}

// startThrottledUpdates starts the background goroutine that throttles UI updates
func (app *Application) startThrottledUpdates() {
	go func() {
		for {
			select {
			case <-app.updateStopChan:
				return
			case <-app.updateTicker.C:
				if app.pendingUpdate.CompareAndSwap(true, false) {
					app.Draw()
				}
			}
		}
	}()
}

// RequestDraw requests a UI redraw in a throttled manner
func (app *Application) RequestDraw() {
	app.pendingUpdate.Store(true)
}

// StopThrottledUpdates stops the throttled update mechanism
func (app *Application) StopThrottledUpdates() {
	app.updateTicker.Stop()
	close(app.updateStopChan)
}
