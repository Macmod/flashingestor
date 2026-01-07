package core

import (
	"fmt"
	"os"
	"time"

	"github.com/Macmod/flashingestor/ui"
)

// LogMessage represents a log entry with level
type LogMessage struct {
	Message string
	Level   int // 0 = normal, 1 = verbose
}

// Logger handles message logging to both UI and file.
type Logger struct {
	channel      chan LogMessage
	file         *os.File
	uiApp        *ui.Application
	verboseLevel int
}

// NewLogger creates a new logger instance.
func NewLogger(channel chan LogMessage, file *os.File, uiApp *ui.Application, verboseLevel int) *Logger {
	return &Logger{
		channel:      channel,
		file:         file,
		uiApp:        uiApp,
		verboseLevel: verboseLevel,
	}
}

// Start begins processing log messages.
func (l *Logger) Start() {
	for logMsg := range l.channel {
		// Skip verbose messages if verbose level is too low
		if logMsg.Level > l.verboseLevel {
			continue
		}

		// Always update UI
		l.uiApp.UpdateLog(logMsg.Message)

		// Write to log file if specified
		if l.file != nil {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			fmt.Fprintf(l.file, "[%s] %s\n", timestamp, logMsg.Message)
		}
	}
}

// OpenLogFile opens a log file for appending.
func OpenLogFile(filename string) (*os.File, error) {
	return os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
}
