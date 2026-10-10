package hiddencode

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/safedep/vet/v2/internal/plugins/internal/agentfiles"
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

// IDs returns every control id of a signal.
func IDs() []string {
	return []string{IDPaddedCode, IDDisguisedScript, IDInvisibleUnicode, IDUnicodeDecoder, IDHistoryRewrite}
}

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
		return append(padded(data), invisible(p, data)...)
	case Asset:
		return disguised(p, data)
	case Source:
		return invisible(p, data)
	case Script:
		return historyRewrite(p, data)
	}
	return nil
}

// rewriteScripts are the file names of the PolinRider script that folds
// its change into the last commit of the victim and force-pushes it.
var rewriteScripts = map[string]bool{"temp_auto_push.bat": true, "temp_interactive_push.bat": true}

var (
	amend    = regexp.MustCompile(`\bcommit\b[^\n]*--amend\b`)
	noVerify = regexp.MustCompile(`--no-verify\b`)
	force    = regexp.MustCompile(`\bpush\b[^\n]*(\s-[a-zA-Z]*f[a-zA-Z]*\b|--force\b)`)
	// clock is a change of the system clock or of the commit date, so the
	// amended commit keeps the time of the original.
	clock = regexp.MustCompile(`(?i)(^|[\s&|;(])(date|time)\s+[^\s/]|Set-Date|GIT_COMMITTER_DATE|LAST_COMMIT_DATE`)
)

// historyRewrite finds the PolinRider script that rewrites the last commit
// of a repository: by its name, by the entries that hide it in .gitignore,
// or by what it runs. The rewrite keeps the author, the date and the
// message, so the force-push shows no new commit.
func historyRewrite(p string, data []byte) []Signal {
	base := path.Base(p)
	if rewriteScripts[strings.ToLower(base)] {
		return []Signal{{ID: IDHistoryRewrite, Line: 1, Title: "The file has the name of the PolinRider script that rewrites the last commit and force-pushes it"}}
	}
	lines := bytes.Split(data, []byte("\n"))
	if base == ".gitignore" {
		entries := map[string]int{}
		for i, l := range lines {
			entries[strings.ToLower(strings.TrimPrefix(strings.TrimSpace(string(l)), "/"))] = i + 1
		}
		for name := range rewriteScripts {
			if line, ok := entries[name]; ok {
				return []Signal{{ID: IDHistoryRewrite, Line: line, Visible: name, Title: ".gitignore hides " + name + ", the PolinRider script that rewrites the last commit"}}
			}
		}
		if line, ok := entries["config.bat"]; ok && entries["branch_structure.json"] > 0 {
			return []Signal{{ID: IDHistoryRewrite, Line: line, Visible: "config.bat", Title: ".gitignore hides config.bat and branch_structure.json, the files of the PolinRider push script"}}
		}
		return nil
	}
	if !amend.Match(data) || !noVerify.Match(data) || !force.Match(data) || !clock.Match(data) {
		return nil
	}
	line := 1
	for i, l := range lines {
		if amend.Match(l) {
			line = i + 1
			break
		}
	}
	return []Signal{{ID: IDHistoryRewrite, Line: line, Visible: string(bytes.TrimSpace(lines[line-1])), Title: "The script amends the last commit with no hooks, keeps its date, and force-pushes it"}}
}

// magic are the first bytes of each binary asset type.
var magic = map[string][][]byte{
	".woff":  {[]byte("wOFF")},
	".woff2": {[]byte("wOF2")},
	".ttf":   {{0, 1, 0, 0}, []byte("true"), []byte("ttcf")},
	".otf":   {[]byte("OTTO"), {0, 1, 0, 0}},
	".png":   {[]byte("\x89PNG")},
	".jpg":   {{0xFF, 0xD8, 0xFF}},
	".jpeg":  {{0xFF, 0xD8, 0xFF}},
	".gif":   {[]byte("GIF8")},
	".ico":   {{0, 0, 1, 0}, {0, 0, 2, 0}},
	".bmp":   {[]byte("BM")},
	".webp":  {[]byte("RIFF")},
}

// lfsPointer starts a Git LFS pointer file, which stands in for a binary
// asset in a checkout with no LFS.
var lfsPointer = []byte("version https://git-lfs.github.com/spec/")

// scriptToken is a sign of a script in a text asset, such as a dictionary
// file, which holds one word on each line.
var scriptToken = regexp.MustCompile(`require\(|eval\(|Function\(|global\[|process\.|child_process|=>|\bfunction\b|\bvar \w+\s*=`)

// disguised finds a script in a font, an image or a dictionary file. The
// Contagious Interview tasks run node on such a file, so the folder looks
// like it holds only assets.
func disguised(p string, data []byte) []Signal {
	ext := strings.ToLower(path.Ext(p))
	want, binary := magic[ext]
	if !binary {
		// A dictionary is text. A long line or a script token is not a word
		// list.
		for i, line := range bytes.Split(data, []byte("\n")) {
			if len(line) > 500 || scriptToken.Match(line) {
				return []Signal{{ID: IDDisguisedScript, Line: i + 1, Title: fmt.Sprintf("The %s file holds a script, not a word list", ext)}}
			}
		}
		return nil
	}
	for _, m := range want {
		if bytes.HasPrefix(data, m) {
			return nil
		}
	}
	if bytes.HasPrefix(data, lfsPointer) || !text(data) {
		return nil
	}
	title := fmt.Sprintf("The file has a %s name but holds text, not a %s file", ext, ext[1:])
	if tabs := len(data) - len(bytes.TrimLeft(data, " \t\r\n")); tabs > 0 {
		title += fmt.Sprintf(", after %d leading spaces and tabs", tabs)
	}
	return []Signal{{ID: IDDisguisedScript, Line: 1, Title: title}}
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

// invisibleKind is the kind of an invisible character.
type invisibleKind int

const (
	visible invisibleKind = iota
	// selector is a variation selector. GlassWorm puts one byte of a
	// payload in each one.
	selector
	// tag is a Unicode tag character. It can spell hidden ASCII text.
	tag
	// zeroWidth is a zero-width space, joiner or no-break space.
	zeroWidth
	// bidi is a bidirectional control. It can show code in another order
	// than the compiler reads it (Trojan Source, CVE-2021-42574).
	bidi
)

func kindOf(r rune) invisibleKind {
	switch {
	case r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0100 && r <= 0xE01EF:
		return selector
	case r >= 0xE0000 && r <= 0xE007F:
		return tag
	case r >= 0x200B && r <= 0x200D, r == 0x2060, r == 0xFEFF:
		return zeroWidth
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return bidi
	}
	return visible
}

const (
	// minRun is the shortest run of invisible characters that hides text.
	// An emoji sequence uses at most two in a row.
	minRun = 4
	// minPayload is the shortest run of selectors or tags that carries a
	// payload for a decoder.
	minPayload = 16
	// blackFlag starts a subdivision flag emoji, such as the flag of
	// England, which spells its region in tag characters.
	blackFlag = 0x1F3F4
	cancelTag = 0xE007F
)

// decoder is a sign of code that turns invisible characters into a payload.
var decoder = regexp.MustCompile(`(?i)codePointAt|fromCodePoint|0xfe0[0f]|0xe01[0-9a-f]{2}|\\u\{e01|\beval\s*\(|\bFunction\s*\(|\bexec\s*\(`)

// invisible finds the longest run of invisible characters, and the first
// bidi control of a code file. An agent instruction file can hold right to
// left text, so only a run counts there.
func invisible(p string, data []byte) []Signal {
	if !mayHoldInvisible(data) {
		return nil
	}
	t, isAgentFile := agentfiles.Classify(p)
	code := !isAgentFile || t != agentfiles.Instructions
	var longestLine, longest, longestPayload, bidiLine int
	line, start, cur, payload := 1, 0, 0, 0
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		i += size
		if r == blackFlag {
			i += flagTags(data[i:])
		}
		k := kindOf(r)
		if r == 0xFEFF && i == size {
			k = visible
		}
		if k == visible {
			if cur > longest {
				longestLine, longest, longestPayload = start, cur, payload
			}
			cur, payload = 0, 0
			if r == '\n' {
				line++
			}
			continue
		}
		if cur == 0 {
			start = line
		}
		cur++
		if k == selector || k == tag {
			payload++
		}
		if k == bidi && code && bidiLine == 0 {
			bidiLine = line
		}
	}
	if cur > longest {
		longestLine, longest, longestPayload = start, cur, payload
	}
	var out []Signal
	if longest >= minRun {
		id, title := IDInvisibleUnicode, fmt.Sprintf("Line %d holds a run of %d invisible characters", longestLine, longest)
		if longestPayload >= minPayload && decoder.Match(data) {
			id, title = IDUnicodeDecoder, fmt.Sprintf("Line %d hides a payload in %d invisible characters, and the file holds a decoder", longestLine, longest)
		}
		out = append(out, Signal{ID: id, Line: longestLine, Title: title, Visible: visibleLine(data, longestLine)})
	}
	if bidiLine > 0 {
		out = append(out, Signal{
			ID: IDInvisibleUnicode, Line: bidiLine, Visible: visibleLine(data, bidiLine),
			Title: fmt.Sprintf("Line %d holds a bidirectional control that can show code in another order", bidiLine),
		})
	}
	return out
}

// mayHoldInvisible is a fast check for the lead bytes of the invisible
// characters in UTF-8: E2 for zero-width and bidi, EF for FE00-FEFF, F3 for
// tags and the selector supplement.
func mayHoldInvisible(data []byte) bool {
	return bytes.IndexByte(data, 0xE2) >= 0 || bytes.IndexByte(data, 0xEF) >= 0 || bytes.IndexByte(data, 0xF3) >= 0
}

// flagTags returns the size of the tag characters of a subdivision flag
// emoji after its black flag: up to 7 tags and the cancel tag. It returns 0
// when the tags do not end with a cancel tag.
func flagTags(data []byte) int {
	n := 0
	for count := 0; count < 8 && n < len(data); count++ {
		r, size := utf8.DecodeRune(data[n:])
		if kindOf(r) != tag {
			return 0
		}
		n += size
		if r == cancelTag {
			return n
		}
	}
	return 0
}

// visibleLine returns a line with no invisible character, cut to 200 bytes.
func visibleLine(data []byte, n int) string {
	lines := bytes.SplitN(data, []byte("\n"), n+1)
	if n > len(lines) {
		return ""
	}
	l := strings.Map(func(r rune) rune {
		if kindOf(r) != visible {
			return -1
		}
		return r
	}, strings.TrimSpace(string(lines[n-1])))
	if len(l) > 200 {
		l = l[:197] + "..."
	}
	return l
}
