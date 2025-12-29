package bloodhound

import (
	"bufio"
	"encoding/json"
	"os"
	"strconv"
)

// BHFormatWriter writes BloodHound JSON objects with streaming and buffering.
type BHFormatWriter struct {
	file     *os.File
	buffer   *bufio.Writer
	count    int
	started  bool
	typeName string
	version  int
}

// NewBHFormatWriter creates a buffered writer for BloodHound JSON output.
func NewBHFormatWriter(filename, typeName string, version int, bufferSize int) (*BHFormatWriter, error) {
	f, err := os.Create(filename)
	if err != nil {
		return nil, err
	}

	buffer := bufio.NewWriterSize(f, bufferSize)
	w := &BHFormatWriter{
		file:     f,
		buffer:   buffer,
		typeName: typeName,
		version:  version,
	}

	if _, err = w.buffer.WriteString(`{"data":[`); err != nil {
		buffer.Flush()
		f.Close()
		return nil, err
	}

	return w, nil
}

func (w *BHFormatWriter) Add(obj any) error {
	if w.started {
		if _, err := w.buffer.WriteString(","); err != nil {
			return err
		}
	} else {
		w.started = true
	}

	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}

	if _, err = w.buffer.Write(data); err != nil {
		return err
	}

	w.count++
	return nil
}

func (w *BHFormatWriter) Close() error {
	if _, err := w.buffer.WriteString(`],"meta":{"type":"`); err != nil {
		return err
	}
	if _, err := w.buffer.WriteString(w.typeName); err != nil {
		return err
	}
	if _, err := w.buffer.WriteString(`","count":`); err != nil {
		return err
	}
	if _, err := w.buffer.WriteString(strconv.Itoa(w.count)); err != nil {
		return err
	}
	if _, err := w.buffer.WriteString(`,"version":`); err != nil {
		return err
	}
	if _, err := w.buffer.WriteString(strconv.Itoa(w.version)); err != nil {
		return err
	}
	if _, err := w.buffer.WriteString("}}"); err != nil {
		return err
	}

	if err := w.buffer.Flush(); err != nil {
		w.file.Close()
		return err
	}

	return w.file.Close()
}
