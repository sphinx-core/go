// MIT License
//
// # Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/logger.go
package logger

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// LogLevel defines the severity level of the log message.
type LogLevel int

// Log level constants starting from 0 with iota.
const (
	DEBUG LogLevel = iota // Detailed debug information.
	INFO                  // General informational messages.
	WARN                  // Warnings about potential issues.
	ERROR                 // Error messages.
)

// levelNames associates LogLevel constants with string labels.
var levelNames = [...]string{"DEBUG", "INFO", "WARN", "ERROR"}

// Global variables for the logger state:

// currentLevel holds the minimum log level to output.
var currentLevel = INFO

// buffer holds the in-memory buffer for log messages.
var buffer = &LogBuffer{}

// mu protects the log output to avoid interleaving log messages.
var mu sync.Mutex

// loggerOut is the multi-writer that writes logs both to stdout and the buffer.
var loggerOut io.Writer = io.MultiWriter(os.Stdout, buffer)

// LogBuffer is a thread-safe bytes.Buffer to store logs in memory.
type LogBuffer struct {
	mu  sync.Mutex   // protects buf
	buf bytes.Buffer // underlying buffer
}

// Write implements io.Writer interface for LogBuffer.
// It writes bytes into the buffer in a thread-safe manner.
func (l *LogBuffer) Write(p []byte) (n int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

// String returns the current contents of the buffer as a string.
// It locks the buffer during read to prevent race conditions.
func (l *LogBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// SetLevel sets the global logging level.
// Messages below this level will be ignored.
func SetLevel(lvl LogLevel) {
	currentLevel = lvl
}

// Infof logs a formatted message at INFO level.
func Infof(format string, args ...any) {
	logf(INFO, format, args...)
}

// Errorf logs a formatted message at ERROR level.
func Errorf(format string, args ...any) {
	logf(ERROR, format, args...)
}

// Fatalf logs a formatted message at ERROR level and then terminates the program.
func Fatalf(format string, args ...any) {
	logf(ERROR, format, args...)
	os.Exit(1)
}

// Debugf logs a formatted message at DEBUG level.
func Debugf(format string, args ...any) {
	logf(DEBUG, format, args...)
}

// Warnf logs a formatted message at WARN level.
func Warnf(format string, args ...any) {
	logf(WARN, format, args...)
}

// Init sets up redirection of os.Stdout and os.Stderr to the logger.
// It captures output written to those file descriptors and logs them at INFO level.
func Init() {
	// Create a pipe (reader and writer ends)
	r, w, err := os.Pipe()
	if err != nil {
		log.Fatalf("Failed to create pipe: %v", err)
	}

	// Redirect stdout and stderr to the write end of the pipe
	os.Stdout = w
	os.Stderr = w

	// Set the standard log package output to our multi-writer
	log.SetOutput(loggerOut)

	// Start a goroutine to read from the pipe asynchronously
	go func() {
		buf := make([]byte, 1024) // buffer for reading pipe
		for {
			n, err := r.Read(buf) // read bytes from pipe
			if err != nil {
				// Exit goroutine on read error (e.g. pipe closed)
				break
			}
			output := string(buf[:n])
			// Split output by newline to log each line separately
			for _, line := range strings.Split(output, "\n") {
				// Ignore empty or whitespace-only lines
				if len(strings.TrimSpace(line)) > 0 {
					// Log captured stdout/stderr lines at INFO level
					Info("%s", line)
				}
			}
		}
	}()
}

// logf is the internal function that actually formats and writes log messages.
// It respects the current log level, prefixes the message with timestamp and level name,
// and writes to the configured logger output.
func logf(level LogLevel, format string, args ...any) {
	// Skip logging if level is below the currentLevel
	if level < currentLevel {
		return
	}

	mu.Lock()
	defer mu.Unlock()

	// Format current time with millisecond precision
	ts := time.Now().Format("2006-01-02 15:04:05.000")

	// Prepare prefix string with timestamp and level label
	prefix := fmt.Sprintf("%s [%s] ", ts, levelNames[level])

	// Format the user message with supplied arguments
	msg := fmt.Sprintf(format, args...)

	// Ensure message ends with newline for proper log formatting
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}

	// Write full log line (prefix + message) to output (stdout + buffer)
	_, _ = fmt.Fprint(loggerOut, prefix+msg)
}

// Convenience exported functions to log with simpler names:

// Debug logs a DEBUG level message.
func Debug(format string, args ...any) { logf(DEBUG, format, args...) }

// Info logs an INFO level message.
func Info(format string, args ...any) { logf(INFO, format, args...) }

// Warn logs a WARN level message.
func Warn(format string, args ...any) { logf(WARN, format, args...) }

// Error logs an ERROR level message.
func Error(format string, args ...any) { logf(ERROR, format, args...) }

// GetLogs returns the full log content accumulated in the in-memory buffer.
// Useful for retrieving all logs for inspection or testing.
func GetLogs() string {
	return buffer.String()
}
