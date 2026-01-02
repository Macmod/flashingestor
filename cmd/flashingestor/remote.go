package main

import (
	"os"
	"strings"
	"time"

	"github.com/Macmod/flashingestor/bloodhound"
	"github.com/Macmod/flashingestor/config"
	"github.com/Macmod/flashingestor/core"
	"github.com/Macmod/flashingestor/ui"
)

// RemoteCollectionManager handles remote data collection.
type RemoteCollectionManager struct {
	bhInst  *bloodhound.BH
	auth    *config.CredentialMgr
	logFunc func(string, ...interface{})
}

func newRemoteCollectionManager(
	bhInst *bloodhound.BH,
	auth *config.CredentialMgr,
	logFunc func(string, ...interface{}),
) *RemoteCollectionManager {
	return &RemoteCollectionManager{
		bhInst:  bhInst,
		auth:    auth,
		logFunc: logFunc,
	}
}

// checkMsgpackFilesExist checks if any .msgpack files exist in the remote folder
func (r *RemoteCollectionManager) checkMsgpackFilesExist() (bool, error) {
	remoteFolder := r.bhInst.ActiveFolder
	entries, err := os.ReadDir(remoteFolder)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".msgpack") {
			return true, nil
		}
	}

	return false, nil
}

func (r *RemoteCollectionManager) start(uiApp *ui.Application) {
	r.bhInst.ResetAbortFlag()
	uiApp.SetRunning(true, "remote")
	uiApp.SetAbortCallback(func() {
		if r.bhInst.RequestAbort() {
			r.logFunc("🛑 [red]Abort requested for remote collection...[-]")
		}
	})

	r.logFunc("💻 [cyan]Starting remote collection...[-]")

	go func() {
		defer func() {
			uiApp.SetAbortCallback(nil)
			uiApp.SetRunning(false, "")
		}()

		processStartTime := time.Now()
		r.bhInst.PerformRemoteCollection(r.auth)
		processDuration := time.Since(processStartTime)

		if r.bhInst.IsAborted() {
			r.logFunc("🛑 [red]Remote collection aborted after %s. Results may be incomplete.[-]", core.FormatDuration(processDuration))
		} else {
			r.logFunc("✅ [green]Remote collection completed in %s[-]", core.FormatDuration(processDuration))
		}
	}()
}
