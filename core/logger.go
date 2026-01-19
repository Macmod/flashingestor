package core

import (
	"fmt"
	"os"
	"time"
)

// LogMessage represents a log entry with level
type LogMessage struct {
	Message string
	Level   int
}

// Logger handles message logging to both UI and file.
type Logger struct {
	channel      chan LogMessage
	file         *os.File
	logCallback  func(string)
	verboseLevel int
}

// NewLogger creates a new logger instance.
func NewLogger(channel chan LogMessage, file *os.File, logCallback func(string), verboseLevel int) *Logger {
	return &Logger{
		channel:      channel,
		file:         file,
		logCallback:  logCallback,
		verboseLevel: verboseLevel,
	}
}

// Log0 sends a normal log message (level 0).
func (l *Logger) Log0(format string, args ...interface{}) {
	l.channel <- LogMessage{Message: fmt.Sprintf(format, args...), Level: 0}
}

// Log1 sends a verbose log message (level 1).
func (l *Logger) Log1(format string, args ...interface{}) {
	l.channel <- LogMessage{Message: fmt.Sprintf(format, args...), Level: 1}
}

// Log2 sends a debug log message (level 2).
func (l *Logger) Log2(format string, args ...interface{}) {
	l.channel <- LogMessage{Message: fmt.Sprintf(format, args...), Level: 2}
}

// Start begins processing log messages.
func (l *Logger) Start() {
	for logMsg := range l.channel {
		// Skip verbose messages if verbose level is too low
		if logMsg.Level > l.verboseLevel {
			continue
		}

		// Call callback if provided
		if l.logCallback != nil {
			l.logCallback(logMsg.Message)
		}

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
