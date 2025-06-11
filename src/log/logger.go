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

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

var levelNames = [...]string{"DEBUG", "INFO", "WARN", "ERROR"}

var (
	currentLevel = INFO
	buffer       = &LogBuffer{}
	mu           sync.Mutex
	loggerOut    io.Writer = io.MultiWriter(os.Stdout, buffer)
)

type LogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *LogBuffer) Write(p []byte) (n int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *LogBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func SetLevel(lvl LogLevel) {
	currentLevel = lvl
}

func logf(level LogLevel, format string, args ...any) {
	if level < currentLevel {
		return
	}

	mu.Lock()
	defer mu.Unlock()

	ts := time.Now().Format("2006-01-02 15:04:05.000")
	prefix := fmt.Sprintf("%s [%s] ", ts, levelNames[level])
	msg := fmt.Sprintf(format, args...)

	// Add newline if not already present
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}

	_, _ = fmt.Fprint(loggerOut, prefix+msg)
}

// Exported logging functions
func Debug(format string, args ...any) { logf(DEBUG, format, args...) }
func Info(format string, args ...any)  { logf(INFO, format, args...) }
func Warn(format string, args ...any)  { logf(WARN, format, args...) }
func Error(format string, args ...any) { logf(ERROR, format, args...) }

// Optional: Initialize standard log package (if needed elsewhere)
func Init() {
	log.SetOutput(loggerOut)
	log.SetFlags(0) // Disable default flags to avoid duplicate timestamps
}

func GetLogs() string {
	return buffer.String()
}
