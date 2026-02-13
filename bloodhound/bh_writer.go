package bloodhound

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/Macmod/flashingestor/core"
	"github.com/vmihailenco/msgpack"
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

// domainWriter holds file, buffer, and encoder for domain-specific output files
type domainWriter struct {
	file      *os.File
	bufWriter *bufio.Writer
	encoder   *msgpack.Encoder
}

// domainWriterManager manages domain-specific writers with lazy creation
type domainWriterManager struct {
	baseDir  string
	filename string
	writers  map[string]*domainWriter
	mu       sync.Mutex
	logger   *core.Logger
}

// newDomainWriterManager creates a new manager for domain-specific writers
func newDomainWriterManager(baseDir, filename string, logger *core.Logger) *domainWriterManager {
	return &domainWriterManager{
		baseDir:  baseDir,
		filename: filename,
		writers:  make(map[string]*domainWriter),
		logger:   logger,
	}
}

// Get returns or creates a writer for the specified domain
func (m *domainWriterManager) Get(domain string) (*domainWriter, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if writer, exists := m.writers[domain]; exists {
		return writer, nil
	}

	// Create domain directory
	domainDir := filepath.Join(m.baseDir, domain)
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		return nil, fmt.Errorf("create domain directory: %w", err)
	}

	// Create output file for this domain
	filePath := filepath.Join(domainDir, m.filename)
	outFile, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("create file: %w", err)
	}

	bufWriter := bufio.NewWriterSize(outFile, 1024*1024)
	encoder := msgpack.NewEncoder(bufWriter)

	writer := &domainWriter{
		file:      outFile,
		bufWriter: bufWriter,
		encoder:   encoder,
	}
	m.writers[domain] = writer
	return writer, nil
}

// Close flushes and closes all writers
func (m *domainWriterManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for domain, writer := range m.writers {
		writer.bufWriter.Flush()
		writer.file.Close()

		filePath := filepath.Join(m.baseDir, domain, m.filename)
		if fileInfo, err := os.Stat(filePath); err == nil {
			m.logger.Log0("✅ [green]%s results for %s saved to: %s (%s)[-]",
				m.filenameLabel(), domain, filePath, formatFileSize(fileInfo.Size()))
		} else {
			m.logger.Log0("🫠 [yellow]Problem saving %s: %v[-]", filePath, err)
		}
	}
}

// filenameLabel returns a friendly label based on the filename
func (m *domainWriterManager) filenameLabel() string {
	switch m.filename {
	case "RemoteEnterpriseCA.msgpack":
		return "EnterpriseCA"
	case "RemoteComputers.msgpack":
		return "Computer"
	case "RemoteGPOChanges.msgpack":
		return "GPOLocalGroup"
	default:
		return "Remote"
	}
}
