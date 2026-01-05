package ui

import (
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// SetButtonCallbacks sets the callback functions for all buttons
func (app *Application) SetButtonCallbacks(ingestionCallback, conversionCallback, remoteCollectionCallback, clearCacheCallback func()) {
	app.ingestionCb = ingestionCallback
	app.conversionCb = conversionCallback
	app.remoteCollectionCb = remoteCollectionCallback
	app.clearCacheCb = clearCacheCallback

	if ingestionCallback != nil {
		app.startIngButton.SetSelectedFunc(func() {
			app.showConfirmModal("Start LDAP Ingestion?", "This will begin collecting data from the LDAP server.", ingestionCallback)
		})
	}

	if conversionCallback != nil {
		app.startConvButton.SetSelectedFunc(func() {
			// Convert doesn't need confirmation
			conversionCallback()
		})
	}

	if remoteCollectionCallback != nil {
		app.startRemoteButton.SetSelectedFunc(func() {
			app.showConfirmModal("Start Remote Collection?", "This will perform active collection on ALL discovered computers. Continue?", remoteCollectionCallback)
		})
	}
}

// DisableIngestion disables the ingestion button
func (app *Application) DisableIngestion() {
	greyStyle := tcell.StyleDefault.Background(tcell.ColorGray).Foreground(tcell.ColorBlack)
	app.startIngButton.SetStyle(greyStyle).SetActivatedStyle(greyStyle)
	app.startIngButton.SetSelectedFunc(func() {})
}

// DisableRemoteCollection disables the remote collection button
func (app *Application) DisableRemoteCollection() {
	greyStyle := tcell.StyleDefault.Background(tcell.ColorGray).Foreground(tcell.ColorBlack)
	app.startRemoteButton.SetStyle(greyStyle).SetActivatedStyle(greyStyle)
	app.startRemoteButton.SetSelectedFunc(func() {})
}

// SetAbortCallback updates the function invoked when the Abort button is pressed.
func (app *Application) SetAbortCallback(callback func()) {
	app.abortCallback = callback
}

// showConfirmModal displays a confirmation dialog before executing an action
func (app *Application) showConfirmModal(title, message string, onConfirm func()) {
	modal := tview.NewModal().
		SetText(message).
		AddButtons([]string{"Confirm", "Cancel"}).
		SetButtonStyle(tcell.StyleDefault.Background(tcell.ColorBlue).Foreground(tcell.ColorBlack)).
		SetButtonActivatedStyle(tcell.StyleDefault.Background(tcell.ColorWhite).Foreground(tcell.ColorBlue)).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			// Remove the modal page
			app.mainPages.RemovePage("modal")
			if buttonLabel == "Confirm" {
				onConfirm()
			}
		})

	modal.SetBorder(true).SetTitle(title)

	// Add modal as an overlay
	app.mainPages.AddPage("modal", modal, true, true)
}

// ShowYesNoModal displays a yes/no confirmation dialog and calls the appropriate callback
func (app *Application) ShowYesNoModal(title, message string, onYes func(), onNo func()) {
	modal := tview.NewModal().
		SetText(message).
		AddButtons([]string{"Yes", "No"}).
		SetButtonStyle(tcell.StyleDefault.Background(tcell.ColorBlue).Foreground(tcell.ColorBlack)).
		SetButtonActivatedStyle(tcell.StyleDefault.Background(tcell.ColorWhite).Foreground(tcell.ColorBlue)).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			// Remove the modal page
			app.mainPages.RemovePage("modal")
			if buttonLabel == "Yes" && onYes != nil {
				onYes()
			} else if buttonLabel == "No" && onNo != nil {
				onNo()
			}
		})

	modal.SetBorder(true).SetTitle(title)

	// Add modal as an overlay
	app.mainPages.AddPage("modal", modal, true, true)
}

// SetRunning enables or disables all buttons based on whether an operation is running
func (app *Application) SetRunning(running bool, operationName string) {
	app.isRunning = running

	if running {
		// Update status text
		var statusText string
		switch operationName {
		case "ingestion":
			statusText = " [blue]LDAP Ingestion in progress...[-]"
			app.SwitchToPage("ingest")
		case "conversion":
			statusText = " [blue]BloodHound Conversion in progress...[-]"
			app.SwitchToPage("conversion")
		case "remote":
			statusText = " [blue]Remote Collection in progress...[-]"
			app.SwitchToPage("remote")
		}

		// Update status panel text
		statusTextView := app.statusPanel.GetItem(0).(*tview.TextView)
		statusTextView.SetText(statusText)

		// Rebuild root flex with status panel
		app.statusPanel.SetBorder(true).SetBorderColor(tcell.ColorWhite)
		/*
			app.statusPanel.
				SetFocusFunc(func() {
					app.statusPanel.SetBorderColor(tcell.ColorBlue)
				}).
				SetBlurFunc(func() {
					app.statusPanel.SetBorderColor(tcell.ColorWhite)
				})
		*/

		app.rootFlex = tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(app.statusPanel, 3, 0, false).
			AddItem(app.progressTracker, 15, 0, false).
			AddItem(app.logPanel, 0, 1, false)

		app.rootFlex.SetTitle("FlashIngestor").
			SetBorder(true).
			SetBorderColor(tcell.ColorWhite)

		app.mainPages.AddAndSwitchToPage("main", app.rootFlex, true)
	} else {
		// Rebuild root flex with button panel
		app.rootFlex = tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(app.buttonPanel, 3, 0, false).
			AddItem(app.progressTracker, 15, 0, false).
			AddItem(app.logPanel, 0, 1, false)

		app.rootFlex.SetTitle("FlashIngestor").
			SetBorder(true).
			SetBorderColor(tcell.ColorWhite)

		app.mainPages.AddAndSwitchToPage("main", app.rootFlex, true)
	}
}
