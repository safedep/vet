package hiddencode

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"regexp"
)

// Control ids of the hidden-code findings. The control plugin owns the
// descriptions.
const (
	IDPaddedCode       = "padded-code"
	IDDisguisedScript  = "disguised-script"
	IDInvisibleUnicode = "invisible-unicode"
	IDUnicodeDecoder   = "unicode-decoder"
	IDHistoryRewrite   = "history-rewrite-script"
)

// Signal is one sign of hidden code in a file.
type Signal struct {
	// ID is the control id of the finding.
	ID    string
	Line  int
	Title string
	// Visible is the text of the line that a reader sees, up to the hidden
	// part. The finding shows it as the snippet, never the payload.
	Visible string
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
	switch c {
	case Config:
		return padded(data)
	}
	return nil
}

// minPad is the shortest run of spaces or tabs that hides code. The
// PolinRider configs use about 280. A normal config aligns a comment with
// a few spaces.
const minPad = 100

// pad is a run of spaces or tabs followed by more text on the same line.
var pad = regexp.MustCompile(`[ \t]{` + fmt.Sprint(minPad) + `,}[^\s]`)

// afterExport is code on the same line after the export of a config, such
// as "export default config; eval(...)".
var afterExport = regexp.MustCompile(`^\s*(export\s+default\s+[\w$.]+|module\.exports\s*=\s*[\w$.]+)\s*;\s*\S`)

// padded finds code that a config hides after a run of spaces or after its
// export.
func padded(data []byte) []Signal {
	if len(data) > MaxSize {
		return []Signal{{ID: IDPaddedCode, Line: 1, Title: fmt.Sprintf("The config is larger than %d MiB. A real config is a few KiB", MaxSize>>20)}}
	}
	var out []Signal
	for i, line := range bytes.Split(data, []byte("\n")) {
		if loc := pad.FindIndex(line); loc != nil {
			run := loc[1] - 1 - loc[0]
			out = append(out, Signal{
				ID: IDPaddedCode, Line: i + 1, Visible: string(bytes.TrimSpace(line[:loc[0]])),
				Title: fmt.Sprintf("Code continues on line %d after %d spaces, with %d bytes off screen", i+1, run, len(line)-loc[1]+1),
			})
			continue
		}
		if loc := afterExport.FindIndex(line); loc != nil {
			hidden := loc[1] - 1
			out = append(out, Signal{
				ID: IDPaddedCode, Line: i + 1, Visible: string(bytes.TrimSpace(line[:hidden])),
				Title: fmt.Sprintf("Code continues on line %d after the export of the config, with %d bytes", i+1, len(line)-hidden),
			})
		}
	}
	return out
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
