package ui

// ShowOptionsPanel displays a modal with runtime options that can be edited
/*
func (app *Application) ShowOptionsPanel(opts *config.RuntimeOptions) {
	modal := tview.NewFlex().SetDirection(tview.FlexRow)
	modal.SetBorder(true).
		SetTitle(" Options (Ctrl-O to close) ").
		SetBorderColor(tcell.ColorYellow)

	// Create form for options
	form := tview.NewForm()
	form.SetBorder(false)
	form.SetBackgroundColor(tcell.ColorDefault)

	// Ingestion options
	form.AddTextView("═══ Ingestion ═══", "", 0, 1, true, false)

	// Conversion options
	form.AddTextView("\n═══ Conversion ═══", "", 0, 1, true, false)
	form.AddCheckbox("Merge Remote", opts.Conversion.MergeRemote,
		func(checked bool) {
			opts.Conversion.MergeRemote = checked
		})
	form.AddInputField("Writer Buffer Size", strconv.Itoa(opts.Conversion.WriterBufsize), 20, nil,
		func(text string) {
			if val, err := strconv.Atoi(text); err == nil && val > 0 {
				opts.Conversion.WriterBufsize = val
			}
		})
	form.AddCheckbox("Compress Output", opts.Conversion.CompressOutput,
		func(checked bool) {
			opts.Conversion.CompressOutput = checked
		})
	form.AddCheckbox("Cleanup After Compression", opts.Conversion.CleanupAfterCompression,
		func(checked bool) {
			opts.Conversion.CleanupAfterCompression = checked
		})

	// Instructions text
	instructions := tview.NewTextView().
		SetText("\n[yellow]Press Ctrl-O to close | Changes take effect immediately[-]").
		SetTextAlign(tview.AlignCenter).
		SetDynamicColors(true)

	modal.AddItem(form, 0, 1, true)
	modal.AddItem(instructions, 1, 0, false)

	// Set up key handler to close modal
	modal.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlO || event.Key() == tcell.KeyEscape {
			app.mainPages.RemovePage("options")
			app.SetFocus(app.rootFlex)
			return nil
		}
		return event
	})

	// Calculate modal size (centered, 60% width, 80% height)
	_, _, width, height := app.rootFlex.GetRect()
	modalWidth := width * 60 / 100
	modalHeight := height * 80 / 100
	x := (width - modalWidth) / 2
	y := (height - modalHeight) / 2

	// Create a flex container to center the modal
	centeredModal := tview.NewFlex().
		AddItem(nil, x, 0, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, y, 0, false).
			AddItem(modal, modalHeight, 0, true).
			AddItem(nil, 0, 1, false),
			modalWidth, 0, true).
		AddItem(nil, 0, 1, false)

	app.mainPages.AddPage("options", centeredModal, true, true)
	app.SetFocus(form)
}
*/
