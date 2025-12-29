package ui

import (
	"fmt"
	"sync"
	"time"

	gildap "github.com/Macmod/flashingestor/ldap"
	"github.com/rivo/tview"
)

// UI related constants
var SpinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Spinner handles spinner animations for multiple domain tables
type Spinner struct {
	app          *Application
	tables       map[string]*tview.Table // domain -> table mapping
	statusColumn int
	spinnerIndex int
	runningRows  map[string]map[int]bool // domain -> row -> running state
	mutex        sync.RWMutex
	stopChan     chan struct{}
	jobs         []gildap.QueryJob
	stopped      bool // Track if Stop() has been called
}

// NewSpinner creates a new spinner that can handle multiple domain tables
func NewSpinner(app *Application, jobs []gildap.QueryJob, statusColumn int) *Spinner {
	return &Spinner{
		app:          app,
		tables:       make(map[string]*tview.Table),
		statusColumn: statusColumn,
		runningRows:  make(map[string]map[int]bool),
		stopChan:     make(chan struct{}),
		jobs:         jobs,
	}
}

// NewSingleTableSpinner creates a spinner for a single table (no domain awareness)
func NewSingleTableSpinner(app *Application, table *tview.Table, statusColumn int) *Spinner {
	s := &Spinner{
		app:          app,
		tables:       make(map[string]*tview.Table),
		statusColumn: statusColumn,
		runningRows:  make(map[string]map[int]bool),
		stopChan:     make(chan struct{}),
	}
	s.tables["default"] = table
	s.runningRows["default"] = make(map[int]bool)
	return s
}

// Start begins the spinner animation loop
func (s *Spinner) Start() {
	s.mutex.Lock()
	// If spinner was stopped, reinitialize the stopChan
	if s.stopped {
		s.stopChan = make(chan struct{})
		s.stopped = false
	}
	s.mutex.Unlock()

	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-s.stopChan:
				return
			case <-ticker.C:
				s.updateSpinners()
			}
		}
	}()
}

// Stop stops the spinner animation loop
func (s *Spinner) Stop() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.stopped {
		s.stopped = true
		close(s.stopChan)
	}
}

// RegisterDomain adds a domain's table to the spinner
func (s *Spinner) RegisterDomain(domainName string, table *tview.Table) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.tables[domainName] = table
	s.runningRows[domainName] = make(map[int]bool)
}

// SetRunning marks a row as running for a specific domain and job
func (s *Spinner) SetRunning(domainName string, jobIndex int, running bool) {
	if jobIndex < 0 || jobIndex >= len(s.jobs) {
		return
	}

	row := s.jobs[jobIndex].Row

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Ensure domain is registered
	if _, exists := s.runningRows[domainName]; !exists {
		s.runningRows[domainName] = make(map[int]bool)
	}

	if running {
		s.runningRows[domainName][row] = true
	} else {
		delete(s.runningRows[domainName], row)
	}

	go func() { s.app.Draw() }()
}

// SetRunningRow marks a specific row as running (for single-table spinners)
func (s *Spinner) SetRunningRow(row int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.runningRows["default"]; !exists {
		s.runningRows["default"] = make(map[int]bool)
	}
	s.runningRows["default"][row] = true

	go func() { s.app.Draw() }()
}

// SetDone marks a specific row as done (for single-table spinners)
func (s *Spinner) SetDone(row int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if domainRows, exists := s.runningRows["default"]; exists {
		delete(domainRows, row)
	}
}

// updateSpinners updates the spinner display for all running rows across all domains
func (s *Spinner) updateSpinners() {
	s.mutex.Lock()

	// Check if any rows are running
	hasRunning := false
	for _, domainRows := range s.runningRows {
		if len(domainRows) > 0 {
			hasRunning = true
			break
		}
	}

	if !hasRunning {
		s.mutex.Unlock()
		return
	}

	// Capture the spinner index for this update cycle
	spinIdx := s.spinnerIndex
	s.spinnerIndex++
	s.mutex.Unlock()

	s.app.QueueUpdateDraw(func() {
		s.mutex.RLock()
		defer s.mutex.RUnlock()

		spin := SpinnerFrames[spinIdx%len(SpinnerFrames)]
		status := fmt.Sprintf("[blue]%s Running", spin)

		for domain, domainRows := range s.runningRows {
			table, ok := s.tables[domain]
			if !ok {
				continue
			}
			for row := range domainRows {
				table.GetCell(row, s.statusColumn).SetText(status)
			}
		}
	})
}
