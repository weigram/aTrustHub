package vpn

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// LogEntry is one line of the app's log.
type LogEntry struct {
	At     time.Time
	Source string
	Line   string
}

// LogBus keeps the last lines the app and ZJU-Connect printed, for the
// window's log panel. It is safe from any goroutine.
type LogBus struct {
	mu     sync.Mutex
	limit  int
	lines  []LogEntry
	notify func()
	sink   io.Writer
}

// NewLogBus returns a bus that keeps the last limit lines.
func NewLogBus(limit int) *LogBus {
	if limit <= 0 {
		limit = 500
	}
	return &LogBus{limit: limit}
}

// SetNotify sets what runs after a line is added, which redraws the
// window. It is called from the goroutine that logged.
func (b *LogBus) SetNotify(fn func()) {
	b.mu.Lock()
	b.notify = fn
	b.mu.Unlock()
}

// SetSink also writes every line to w, for a log file kept while the app
// runs. Pass nil to stop.
func (b *LogBus) SetSink(w io.Writer) {
	b.mu.Lock()
	b.sink = w
	b.mu.Unlock()
}

// Add appends one line per line of format.
func (b *LogBus) Add(source, format string) {
	at := time.Now()
	b.mu.Lock()
	for _, line := range strings.Split(strings.TrimRight(format, "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		b.lines = append(b.lines, LogEntry{At: at, Source: source, Line: line})
		if b.sink != nil {
			_, _ = fmt.Fprintf(b.sink, "%s [%s] %s\n", at.Format("2006-01-02 15:04:05"), source, line)
		}
	}
	if over := len(b.lines) - b.limit; over > 0 {
		b.lines = append([]LogEntry(nil), b.lines[over:]...)
	}
	notify := b.notify
	b.mu.Unlock()
	if notify != nil {
		notify()
	}
}

// Upsert adds a line, or refreshes the time of an identical one already in the
// log and moves it to the end, so a repeated access shows once with its latest
// time instead of piling up.
func (b *LogBus) Upsert(source, line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	at := time.Now()
	b.mu.Lock()
	replaced := false
	for i := range b.lines {
		if b.lines[i].Source == source && b.lines[i].Line == line {
			b.lines = append(b.lines[:i], b.lines[i+1:]...)
			replaced = true
			break
		}
	}
	b.lines = append(b.lines, LogEntry{At: at, Source: source, Line: line})
	// Only a first sighting goes to the file; repeats just refresh the panel.
	if b.sink != nil && !replaced {
		_, _ = fmt.Fprintf(b.sink, "%s [%s] %s\n", at.Format("2006-01-02 15:04:05"), source, line)
	}
	if over := len(b.lines) - b.limit; over > 0 {
		b.lines = append([]LogEntry(nil), b.lines[over:]...)
	}
	notify := b.notify
	b.mu.Unlock()
	if notify != nil {
		notify()
	}
}

// Drop removes one line, if present, without touching the rest.
func (b *LogBus) Drop(source, line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	b.mu.Lock()
	for i := range b.lines {
		if b.lines[i].Source == source && b.lines[i].Line == line {
			b.lines = append(b.lines[:i], b.lines[i+1:]...)
			break
		}
	}
	notify := b.notify
	b.mu.Unlock()
	if notify != nil {
		notify()
	}
}

// Tail returns the last n lines, oldest first.
func (b *LogBus) Tail(n int) []LogEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n <= 0 || n > len(b.lines) {
		n = len(b.lines)
	}
	out := make([]LogEntry, n)
	copy(out, b.lines[len(b.lines)-n:])
	return out
}

// Clear empties the log.
func (b *LogBus) Clear() {
	b.mu.Lock()
	b.lines = nil
	b.mu.Unlock()
}

// Writer returns an io.Writer that adds what it receives to the bus under
// source. ZJU-Connect logs through the standard logger, so the app points
// that logger here.
func (b *LogBus) Writer(source string) io.Writer {
	return &busWriter{bus: b, source: source}
}

type busWriter struct {
	bus    *LogBus
	source string
	mu     sync.Mutex
	buf    bytes.Buffer
}

func (w *busWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, _ = w.buf.Write(p)
	for {
		line, err := w.buf.ReadString('\n')
		if err != nil {
			// Keep the partial line until its newline arrives.
			w.buf.Reset()
			_, _ = w.buf.WriteString(line)
			break
		}
		w.bus.Add(w.source, line)
	}
	return len(p), nil
}

// Flush adds what is left of a partial line, at shutdown.
func (w *busWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf.Len() > 0 {
		w.bus.Add(w.source, w.buf.String())
		w.buf.Reset()
	}
}
