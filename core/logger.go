package core

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

// globalVerbosity stores the verbosity level shared by all loggers.
// Access via SetVerbosity() and GetVerbosity() functions.
var globalVerbosity atomic.Int32

// SetVerbosity changes the verbosity level at runtime for all loggers.
// Valid range is 0-2 (0=normal, 1=verbose, 2=debug).
func SetVerbosity(level int) {
	if level < 0 {
		level = 0
	}
	if level > 2 {
		level = 2
	}
	globalVerbosity.Store(int32(level))
}

// GetVerbosity returns the current verbosity level.
func GetVerbosity() int {
	return int(globalVerbosity.Load())
}

func VerbosityString(level int) string {
	switch level {
	case 0:
		return "NORMAL"
	case 1:
		return "VERBOSE"
	case 2:
		return "DEBUG"
	default:
		return fmt.Sprintf("UNKNOWN (%d)", level)
	}
}

// LogMessage represents a log entry with level
type LogMessage struct {
	Message string
	Level   int
}

// Logger handles message logging to both UI and file.
type Logger struct {
	channel     chan LogMessage
	file        *os.File
	logCallback func(string)
}

// NewLogger creates a new logger instance and initializes the global verbosity level.
func NewLogger(channel chan LogMessage, file *os.File, logCallback func(string), verboseLevel int) *Logger {
	globalVerbosity.Store(int32(verboseLevel))

	return &Logger{
		channel:     channel,
		file:        file,
		logCallback: logCallback,
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
		currentLevel := int(globalVerbosity.Load())
		if logMsg.Level > currentLevel {
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
