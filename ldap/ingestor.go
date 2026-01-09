// Package ldap implements LDAP ingestion functionality for Active Directory
// queries and data collection.
package ldap

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/vmihailenco/msgpack/v5"
)

type QueryJob struct {
	Name       string
	BaseDN     string
	Filter     string
	Attributes []string
	PageSize   uint32
	Row        int
	OutputFile string
	BufferSize int // number of entries to buffer before flushing
}

type ProgressUpdate struct {
	Row      int
	Page     int
	Total    int
	Speed    float64
	AvgSpeed float64
	Done     bool
	Aborted  bool
	Err      error
	Elapsed  time.Duration
}

// bufferedWriter writes entries as a single msgpack array without loading all into memory.
// It writes a placeholder length, then entries, then patches the length at the end.
type bufferedWriter struct {
	file      *os.File
	writer    *bufio.Writer
	ch        chan *ldap.Entry
	wg        *sync.WaitGroup
	count     int
	headerPos int64
	enc       *msgpack.Encoder
}

func newBufferedWriter(path string, bufSize int) (*bufferedWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}

	writer := bufio.NewWriterSize(f, 32*1024*1024) // 32MB buffer for disk writes

	bw := &bufferedWriter{
		file:   f,
		writer: writer,
		ch:     make(chan *ldap.Entry, bufSize),
		wg:     &sync.WaitGroup{},
		count:  0,
	}

	// Write msgpack array header with placeholder length (max 5 bytes for array32)
	// We'll write array32 format to support up to 2^32-1 elements
	// Format: 0xdd (array32) + 4 bytes for length
	bw.headerPos = 0
	bw.writer.WriteByte(0xdd)                       // array32 marker
	bw.writer.Write([]byte{0x00, 0x00, 0x00, 0x00}) // placeholder length
	bw.writer.Flush()

	bw.enc = msgpack.NewEncoder(bw.writer)

	bw.wg.Add(1)
	go bw.loop()
	return bw, nil
}

func (bw *bufferedWriter) loop() {
	defer bw.wg.Done()
	for entry := range bw.ch {
		// Encode each entry directly into the msgpack stream
		if err := bw.enc.Encode(entry); err != nil {
			// Log error but continue
			//fmt.Fprintf(os.Stderr, "Error encoding entry: %v\n", err)
		}
		bw.count++
	}
}

func (bw *bufferedWriter) write(entry *ldap.Entry) {
	select {
	case bw.ch <- entry:
	default:
		// if channel is full, block to let it drain
		bw.ch <- entry
	}
}

func (bw *bufferedWriter) close() error {
	close(bw.ch)
	bw.wg.Wait()

	// Flush remaining data
	if err := bw.writer.Flush(); err != nil {
		bw.file.Close()
		return err
	}

	// Now patch the array length at the beginning of the file
	// Seek to position 1 (after the 0xdd marker)
	if _, err := bw.file.Seek(1, 0); err != nil {
		bw.file.Close()
		return err
	}

	// Write the actual count as big-endian uint32
	countBytes := []byte{
		byte(bw.count >> 24),
		byte(bw.count >> 16),
		byte(bw.count >> 8),
		byte(bw.count),
	}

	if _, err := bw.file.Write(countBytes); err != nil {
		bw.file.Close()
		return err
	}

	return bw.file.Close()
}

func PagedSearchWorker(
	ctx context.Context,
	conn *ldap.Conn,
	job QueryJob,
	updates chan<- ProgressUpdate,
	entries chan<- *ldap.Entry,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	defer conn.Close()

	var (
		page      = 0
		total     = 0
		cookie    []byte
		lastTime  = time.Now()
		startTime = time.Now()
		lastCount = 0
	)

	bw, err := newBufferedWriter(job.OutputFile, job.BufferSize)
	if err != nil {
		updates <- ProgressUpdate{Row: job.Row, Err: fmt.Errorf("create writer: %w", err)}
		return
	}

	var lastUpdate *ProgressUpdate
	defer func() {
		// Ensure writer is closed and final update is sent
		if err := bw.close(); err != nil {
			updates <- ProgressUpdate{Row: job.Row, Err: fmt.Errorf("close writer: %w", err)}
			return
		}

		if lastUpdate == nil {
			updates <- ProgressUpdate{Row: job.Row, Done: true, Total: total, Elapsed: time.Since(startTime)}
		} else {
			updates <- *lastUpdate
		}
	}()

	for {
		select {
		case <-ctx.Done():
			lastUpdate = &ProgressUpdate{Row: job.Row, Aborted: true, Total: total, Elapsed: time.Since(startTime)}
			return
		default:
		}

		searchReq := ldap.NewSearchRequest(
			job.BaseDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			job.Filter,
			job.Attributes,
			nil,
		)

		controlPaging := ldap.NewControlPaging(job.PageSize)
		controlPaging.SetCookie(cookie)

		controlSdFlags := ldap.NewControlMicrosoftSDFlags()
		controlSdFlags.ControlValue = 0x5 // DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION

		searchReq.Controls = []ldap.Control{controlPaging, controlSdFlags}

		sr, err := conn.Search(searchReq)
		if err != nil {
			if ctx.Err() != nil {
				lastUpdate = &ProgressUpdate{Row: job.Row, Aborted: true, Total: total, Elapsed: time.Since(startTime)}
			} else {
				lastUpdate = &ProgressUpdate{Row: job.Row, Err: err}
			}
			return
		}

		page++
		total += len(sr.Entries)

		// Queue each entry individually to async writer
		for _, entry := range sr.Entries {
			if entries != nil {
				entries <- entry
			}

			bw.write(entry)
		}

		// Calculate instantaneous speed and avg speed
		now := time.Now()
		elapsed := now.Sub(lastTime).Seconds()
		var speed float64
		var avgSpeed float64
		if elapsed > 0 {
			speed = float64(total-lastCount) / elapsed
		}
		lastTime = now
		lastCount = total
		avgSpeed = float64(total) / now.Sub(startTime).Seconds()

		updates <- ProgressUpdate{
			Row:      job.Row,
			Page:     page,
			Total:    total,
			Speed:    speed,
			AvgSpeed: avgSpeed,
			Elapsed:  time.Since(startTime),
		}

		pagingControl := ldap.FindControl(sr.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		cookie = pagingControl.Cookie
		if len(cookie) == 0 {
			break
		}
	}
}
