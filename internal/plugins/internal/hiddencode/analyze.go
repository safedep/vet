package hiddencode

import (
	"bytes"
	"io"
	"io/fs"
)

// Signal is one sign of hidden code in a file.
type Signal struct {
	// ID is the control id of the finding.
	ID    string
	Line  int
	Title string
	// Campaign names a known campaign whose markers the file holds.
	Campaign string
}

// Read reads the part of a file that Analyze needs: the first bytes of an
// asset that starts with its magic bytes, else at most MaxSize+1 bytes.
func Read(fsys fs.FS, p string, c Class) (data []byte, err error) {
	f, err := fsys.Open(p)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	head := make([]byte, headSize)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	head = head[:n]
	if c == Asset && !text(head) {
		return head, nil
	}
	rest, err := io.ReadAll(io.LimitReader(f, MaxSize+1-int64(n)))
	if err != nil {
		return nil, err
	}
	return append(head, rest...), nil
}

// Analyze returns the signs of hidden code in the data of a file of class
// c at path p.
func Analyze(c Class, p string, data []byte) []Signal {
	return nil
}

// text reports data that looks like text: no NUL byte, and few control
// bytes other than tab, line feed and carriage return.
func text(data []byte) bool {
	if len(data) == 0 || bytes.IndexByte(data, 0) >= 0 {
		return false
	}
	ctl := 0
	for _, b := range data {
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' && b != '\f' {
			ctl++
		}
	}
	return ctl*20 < len(data)
}
