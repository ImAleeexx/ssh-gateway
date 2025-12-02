// Package recorder implements session recording in asciinema format.
package recorder

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Header represents the asciinema format v2 header.
type Header struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp"`
	Env       map[string]string `json:"env,omitempty"`
}

// Event represents a single asciinema event.
type Event struct {
	Time   float64
	Type   string
	Data   string
	offset time.Time
}

// Recorder records terminal sessions in asciinema format.
type Recorder struct {
	file      *os.File
	startTime time.Time
	mu        sync.Mutex
	closed    bool
}

// New creates a new session recorder.
func New(filename string, width, height int, env map[string]string) (*Recorder, error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to create recording file: %w", err)
	}

	r := &Recorder{
		file:      file,
		startTime: time.Now(),
	}

	// Write header
	header := Header{
		Version:   2,
		Width:     width,
		Height:    height,
		Timestamp: r.startTime.Unix(),
		Env:       env,
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}

	if _, err := file.Write(append(headerBytes, '\n')); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to write header: %w", err)
	}

	return r, nil
}

// WriteOutput records output from the terminal.
func (r *Recorder) WriteOutput(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	return r.writeEvent("o", data)
}

// WriteInput records input to the terminal.
func (r *Recorder) WriteInput(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	return r.writeEvent("i", data)
}

func (r *Recorder) writeEvent(eventType string, data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}

	elapsed := time.Since(r.startTime).Seconds()
	event := []interface{}{elapsed, eventType, string(data)}

	eventBytes, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	if _, err := r.file.Write(append(eventBytes, '\n')); err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

// Close closes the recorder and finalizes the recording file.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}

	r.closed = true
	return r.file.Close()
}

// RecordingWriter wraps an io.Writer and records all data written to it.
type RecordingWriter struct {
	writer   io.Writer
	recorder *Recorder
}

// NewRecordingWriter creates a new recording writer.
func NewRecordingWriter(w io.Writer, r *Recorder) *RecordingWriter {
	return &RecordingWriter{
		writer:   w,
		recorder: r,
	}
}

// Write implements io.Writer.
func (w *RecordingWriter) Write(p []byte) (n int, err error) {
	n, err = w.writer.Write(p)
	if n > 0 && w.recorder != nil {
		w.recorder.WriteOutput(p[:n])
	}
	return n, err
}

// RecordingReader wraps an io.Reader and records all data read from it.
type RecordingReader struct {
	reader   io.Reader
	recorder *Recorder
}

// NewRecordingReader creates a new recording reader.
func NewRecordingReader(r io.Reader, rec *Recorder) *RecordingReader {
	return &RecordingReader{
		reader:   r,
		recorder: rec,
	}
}

// Read implements io.Reader.
func (r *RecordingReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	if n > 0 && r.recorder != nil {
		r.recorder.WriteInput(p[:n])
	}
	return n, err
}
