package core

import (
	"fmt"
	"os"
	"time"

	"github.com/Macmod/flashingestor/ui"
)

// Logger handles message logging to both UI and file.
type Logger struct {
	channel chan string
	file    *os.File
	uiApp   *ui.Application
}

// NewLogger creates a new logger instance.
func NewLogger(channel chan string, file *os.File, uiApp *ui.Application) *Logger {
	return &Logger{
		channel: channel,
		file:    file,
		uiApp:   uiApp,
	}
}

// Start begins processing log messages.
func (l *Logger) Start() {
	for msg := range l.channel {
		// Always update UI
		l.uiApp.UpdateLog(msg)

		// Write to log file if specified
		if l.file != nil {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			fmt.Fprintf(l.file, "[%s] %s\n", timestamp, msg)
		}
	}
}

// OpenLogFile opens a log file for appending.
func OpenLogFile(filename string) (*os.File, error) {
	return os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
}
