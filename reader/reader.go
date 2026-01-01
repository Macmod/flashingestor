package reader

import (
	"os"

	"github.com/vmihailenco/msgpack"
)

type MPReader struct {
	file   *os.File
	dec    *msgpack.Decoder
	length int
}

func NewMPReader(filePath string) (*MPReader, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	dec := msgpack.NewDecoder(file)
	return &MPReader{
		file:   file,
		dec:    dec,
		length: 0,
	}, nil
}

func (r *MPReader) ReadLength() (int, error) {
	if r.length == 0 {
		length, err := r.dec.DecodeArrayLen()
		if err != nil {
			return 0, err
		}

		r.length = length
	}

	return r.length, nil
}

func (r *MPReader) ReadEntry(v interface{}) error {
	return r.dec.Decode(v)
}

func (r *MPReader) GetPath() string {
	return r.file.Name()
}

func (r *MPReader) Length() int {
	return r.length
}

func (r *MPReader) Close() error {
	return r.file.Close()
}

/*
// Entries returns a lazy iterator over all entries. ReadLength must be called first.
func (r *MPReader) Entries(entryFactory func() interface{}) iter.Seq2[interface{}, error] {
	return func(yield func(interface{}, error) bool) {
		for i := 0; i < r.length; i++ {
			entry := entryFactory()
			err := r.dec.Decode(entry)
			if !yield(entry, err) {
				return
			}
			if err != nil {
				return
			}
		}
	}
}
*/

/*
func ReadEntries(file *os.File, batchCallback func(int), entryCallback func(dec *msgpack.Decoder) bool, shouldAbort func() bool) {
	dec := msgpack.NewDecoder(file)

	// We loop just for safety, but in theory it
	// should stop on the first iteration
	for {
		if shouldAbort != nil && shouldAbort() {
			return
		}

		length, err := dec.DecodeArrayLen()
		if err != nil {
			break
		}

		if batchCallback != nil {
			batchCallback(length)
		}

		// Stream each element one by one
		for i := 0; i < length; i++ {
			if shouldAbort != nil && shouldAbort() {
				return
			}

			if entryCallback != nil {
				if !entryCallback(dec) {
					continue
				}
			}
		}
	}
}
*/
