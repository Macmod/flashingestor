package main

import (
	"time"

	"github.com/Macmod/flashingestor/bloodhound"
	"github.com/Macmod/flashingestor/core"
	"github.com/Macmod/flashingestor/ui"
)

// ConversionManager handles BloodHound conversion.
type ConversionManager struct {
	bhInst  *bloodhound.BH
	logFunc func(string, ...interface{})
}

func newConversionManager(
	bhInst *bloodhound.BH,
	logFunc func(string, ...interface{}),
) *ConversionManager {
	return &ConversionManager{bhInst: bhInst, logFunc: logFunc}
}

func (c *ConversionManager) start(uiApp *ui.Application) {
	c.bhInst.ResetAbortFlag()
	uiApp.SetRunning(true, "conversion")
	uiApp.SetAbortCallback(func() {
		if c.bhInst.RequestAbort() {
			c.logFunc("🛑 [red]Abort requested for BloodHound conversion...[-]")
		}
	})

	c.logFunc("🔀 [cyan]Starting BloodHound conversion...[-]")

	go func() {
		defer func() {
			uiApp.SetAbortCallback(nil)
			uiApp.SetRunning(false, "")
		}()

		processStartTime := time.Now()
		c.bhInst.PerformConversion()
		processDuration := time.Since(processStartTime)

		if c.bhInst.IsAborted() {
			c.logFunc("🛑 [red]BloodHound conversion aborted after %s[-]", core.FormatDuration(processDuration))
		} else {
			c.logFunc("✅ [green]BloodHound conversion completed in %s[-]", core.FormatDuration(processDuration))

		}
		c.bhInst.ResetAbortFlag()
	}()
}
