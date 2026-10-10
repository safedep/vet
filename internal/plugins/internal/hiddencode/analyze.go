package hiddencode

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/internal/agentfiles"
)

// Control ids of the hidden-code findings. The control plugin owns the
// descriptions.
const (
	IDPaddedCode       = "padded-code"
	IDDisguisedScript  = "disguised-script"
	IDInvisibleUnicode = "invisible-unicode"
	IDUnicodePayload   = "unicode-payload"
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

// Open reads the part of a file of fsys that Analyze needs. See Read.
func Open(fsys fs.FS, p string, c Class) (data []byte, err error) {
	f, err := fsys.Open(p)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	return Read(f, p, c)
}

// Read reads the part of a file that Analyze needs: the first bytes of a
// binary image, else at most MaxSize+1 bytes. A font is small, and a
// script can sit after a binary header in it, so vet reads all of it.
func Read(r io.Reader, p string, c Class) ([]byte, error) {
	head := make([]byte, headSize)
	n, err := io.ReadFull(r, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	head = head[:n]
	if c == Asset && !text(head) && assetOf(p) != font && !commentStart(head) {
		return head, nil
	}
	rest, err := io.ReadAll(io.LimitReader(r, MaxSize+1-int64(n)))
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
		return named(append(append(oversizeConfig(data), padded(data, true)...), invisible(p, data)...), data)
	case Asset:
		return named(disguised(p, data), data)
	case Source:
		return named(append(append(padded(data, false), invisible(p, data)...), rewriteScript(data)...), data)
	case Script:
		return historyRewrite(p, data)
	case Entry:
		return named(append(oversizeEntry(data), padded(data, true)...), data)
	}
	return nil
}

// maxEntry is the largest npm entry script that vet expects. The published
// npm lib/cli.js is a few lines. PolinRider overwrites it with about 1 MB.
const maxEntry = 64 << 10

func oversizeEntry(data []byte) []Signal {
	if len(data) <= maxEntry {
		return nil
	}
	return []Signal{{ID: IDPaddedCode, Line: 1, Title: fmt.Sprintf("The npm entry script is %d KiB. The published file is a few lines", len(data)>>10)}}
}

// rewriteScripts are the file names of the PolinRider script that folds
// its change into the last commit of the victim and force-pushes it.
var rewriteScriptNames = []string{"temp_auto_push.bat", "temp_interactive_push.bat"}

var (
	amend = regexp.MustCompile(`\bcommit\b[^\n]*--amend\b`)
	// noVerify is a commit with no hooks: --no-verify, or its short form -n.
	noVerify = regexp.MustCompile(`\bcommit\b[^\n]*(--no-verify\b|\s-[a-zA-Z]*n\b)`)
	// force is a forced push: -f, --force, or a refspec that starts with +.
	force = regexp.MustCompile(`\bpush\b[^\n]*(\s-[a-zA-Z]*f[a-zA-Z]*\b|--force\b|\s\+[\w/.-]+)`)
	// clock sets the system clock or the commit date, so the amended commit
	// keeps the time of the original. A date in a commit message does not.
	clock = regexp.MustCompile("(?im)(^|[&|;('\"`]\\s*)(date|time)\\s+(%|-s\\b|--set\\b|\\d)|Set-Date|GIT_COMMITTER_DATE=|LAST_COMMIT_DATE|faketime")
)

// historyRewrite finds the PolinRider script that rewrites the last commit
// of a repository: by its name, by the entries that hide it in .gitignore,
// or by what it runs. The rewrite keeps the author, the date and the
// message, so the force-push shows no new commit.
func historyRewrite(p string, data []byte) []Signal {
	base := path.Base(p)
	if slices.Contains(rewriteScriptNames, strings.ToLower(base)) {
		return []Signal{{ID: IDHistoryRewrite, Line: 1, Title: "The file has the name of the PolinRider script that rewrites the last commit and force-pushes it"}}
	}
	if base == ".gitignore" {
		lines := bytes.Split(data, []byte("\n"))
		entries := map[string]int{}
		for i, l := range lines {
			entries[strings.ToLower(strings.TrimPrefix(strings.TrimSpace(string(l)), "/"))] = i + 1
		}
		for _, name := range rewriteScriptNames {
			if line, ok := entries[name]; ok {
				return []Signal{{ID: IDHistoryRewrite, Line: line, Visible: name, Title: ".gitignore hides " + name + ", the PolinRider script that rewrites the last commit"}}
			}
		}
		if line, ok := entries["config.bat"]; ok && entries["branch_structure.json"] > 0 {
			return []Signal{{ID: IDHistoryRewrite, Line: line, Visible: "config.bat", Title: ".gitignore hides config.bat and branch_structure.json, the files of the PolinRider push script"}}
		}
		return nil
	}
	return rewriteScript(data)
}

// rewriteScript finds a script that amends the last commit with no hooks,
// keeps its date, and force-pushes it, in any language.
func rewriteScript(data []byte) []Signal {
	if !bytes.Contains(data, []byte("--amend")) || !amend.Match(data) || !noVerify.Match(data) || !force.Match(data) || !clock.Match(data) {
		return nil
	}
	lines := bytes.Split(data, []byte("\n"))
	line := 1
	for i, l := range lines {
		if amend.Match(l) {
			line = i + 1
			break
		}
	}
	return []Signal{{ID: IDHistoryRewrite, Line: line, Visible: finding.Shorten(string(bytes.TrimSpace(lines[line-1])), maxVisible), Title: "The script amends the last commit with no hooks, keeps its date, and force-pushes it"}}
}

// lfsPointer starts a Git LFS pointer file, which stands in for a binary
// asset in a checkout with no LFS.
var lfsPointer = []byte("version https://git-lfs.github.com/spec/")

// scriptToken is a sign of JavaScript. Each one needs its punctuation, so a
// word list or a fuzz dictionary that holds the word "function" is not a
// script.
var scriptToken = regexp.MustCompile(`require\s*\(|\beval\s*\(|\bFunction\s*\(|global\[|process\.(env|argv|platform)|child_process|=>\s*\{|\bfunction\s*\w*\s*\(|\btry\s*\{|\b(var|let|const)\s+[\w$]+\s*=|console\.\w+\(|_0x[0-9a-f]{4}|String\.fromCharCode|\batob\s*\(|Buffer\.from\(|\bconstructor\b|decodeURIComponent\s*\(|globalThis\[|\bimport\s*\(`)

// strongToken is a sign of a script in binary data. Compressed font data
// holds none of them by chance.
var strongToken = regexp.MustCompile(`require\s*\(\s*['"]|child_process|\beval\s*\(|\(\s*0\s*,\s*eval\s*\)|\bnew Function\s*\(|process\.env\b|\batob\s*\(`)

// encoded reports a long run of hex or base64, as a hex payload that a
// loader reads from a fake font. A loop counts the runs, because a
// repeated regular expression is slow on a long near miss.
func encoded(data []byte) bool {
	hexRun, b64Run := 0, 0
	for _, c := range data {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			hexRun++
			b64Run++
		case c >= 'g' && c <= 'z', c >= 'G' && c <= 'Z', c == '+', c == '/':
			hexRun = 0
			b64Run++
		default:
			hexRun, b64Run = 0, 0
		}
		if hexRun >= 256 || b64Run >= 512 {
			return true
		}
	}
	return false
}

// commentStart reports data that starts with a JavaScript comment or a
// shebang. node runs such a file even with binary bytes in the comment, and
// a real font or image never starts so.
func commentStart(data []byte) bool {
	t := bytes.TrimLeftFunc(bytes.TrimPrefix(data, []byte("\xEF\xBB\xBF")), unicode.IsSpace)
	return bytes.HasPrefix(t, []byte("/*")) || bytes.HasPrefix(t, []byte("//")) || bytes.HasPrefix(t, []byte("#!"))
}

// dictEntry is a line of a fuzz dictionary: a quoted value with an
// optional name, as kw="function".
var dictEntry = regexp.MustCompile(`^\s*([\w-]+\s*=\s*)?".*"\s*$`)

// minScriptLines is the fewest lines of a dictionary with a script token
// that make it a script, when no one line holds two tokens.
const minScriptLines = 3

// maxWordLine is the longest line of a dictionary that holds words. A fuzz
// dictionary can have a line of a few hundred bytes.
const maxWordLine = 2000

// disguised finds a script in a font, an image or a dictionary file. The
// Contagious Interview tasks run node on such a file, so the folder looks
// like it holds only assets. A real font or image holds a NUL byte in its
// first bytes, so text in a binary asset type is the sign, not the magic
// bytes, which a script can start with.
func disguised(p string, data []byte) []Signal {
	ext := strings.ToLower(path.Ext(p))
	sig := func(line int, title string) []Signal {
		return []Signal{{ID: IDDisguisedScript, Line: line, Title: title}}
	}
	kind := assetOf(p)
	if kind == words {
		if !text(data) {
			return nil
		}
		first, lines := 0, 0
		for i, line := range bytes.Split(data, []byte("\n")) {
			if dictEntry.Match(line) {
				continue
			}
			n := len(scriptToken.FindAll(line, 2))
			if n >= 2 || (n == 1 && len(line) > maxWordLine) {
				return sig(i+1, fmt.Sprintf("The %s file holds a script, not a word list", ext))
			}
			if n == 1 {
				if lines == 0 {
					first = i + 1
				}
				lines++
			}
		}
		if lines >= minScriptLines {
			return sig(first, fmt.Sprintf("The %s file holds a script, not a word list", ext))
		}
		return nil
	}
	if !text(data) {
		if (kind == font && strongToken.Match(data)) || (commentStart(data) && scriptToken.Match(data)) {
			return sig(1, fmt.Sprintf("The %s file holds script code after its binary header", ext))
		}
		return nil
	}
	trimmed := bytes.TrimLeftFunc(data, space)
	if bytes.HasPrefix(data, lfsPointer) || bytes.HasPrefix(trimmed, []byte("data:")) ||
		(bytes.HasPrefix(trimmed, []byte("<")) && !bytes.HasPrefix(trimmed, []byte("<!--"))) {
		// A web page or a data URI that a download saved under the name of
		// an image is not a script that node runs.
		// A web page that a download saved under the name of an image is
		// not a script that node runs.
		return nil
	}
	lead := len(data) - len(trimmed)
	if lead < minPad && !scriptToken.Match(data) && !encoded(data) {
		return nil
	}
	title := fmt.Sprintf("The file has a %s name but holds a script or an encoded payload, not a %s file", ext, ext[1:])
	if lead > 0 {
		title += fmt.Sprintf(", after %d leading spaces and tabs", lead)
	}
	return sig(1, title)
}

// minPad is the shortest run of white space that hides code. The
// PolinRider configs use about 280. A normal config aligns a comment with
// a few spaces.
const minPad = 100

// space reports a character that shows as nothing: the white space of
// JavaScript, such as U+00A0 and U+3000, a format character such as a
// zero-width space, and the blank letters such as the Hangul filler and the
// blank braille pattern. Inside a comment or between spaces, each one pads
// a line as well as a space does.
func space(r rune) bool {
	switch r {
	case 0x2800, 0x3164, 0x115F, 0x1160, 0xFFA0:
		return true
	}
	return unicode.IsSpace(r) || unicode.Is(unicode.Cf, r)
}

// tabWidth is the width of a tab in the editor, for the pad count.
const tabWidth = 4

// padRun finds a run of white space at least minPad columns wide followed
// by more text on the line. It returns the byte offsets of the run and its
// width.
func padRun(line []byte) (start, end, count int, ok bool) {
	runStart, n := 0, 0
	for i := 0; i < len(line); {
		r, size := utf8.DecodeRune(line[i:])
		if space(r) {
			if n == 0 {
				runStart = i
			}
			n++
			if r == '\t' {
				n += tabWidth - 1
			}
		} else {
			if n >= minPad {
				return runStart, i, n, true
			}
			n = 0
		}
		i += size
	}
	return 0, 0, 0, false
}

// afterExport is code on the same line after the export of a config, such
// as "export default config; eval(...)".
var afterExport = regexp.MustCompile(`^\s*(export\s+default\s+[\w$.]+|module\.exports\s*=\s*[\w$.]+)\s*;\s*`)

// moreExport is what can follow an export on the same line in a clean
// config: a comment, or one more export.
var moreExport = regexp.MustCompile(`^(//|/\*|module\.exports|exports\.|export\s)`)

func oversizeConfig(data []byte) []Signal {
	if len(data) <= MaxSize {
		return nil
	}
	return []Signal{{ID: IDPaddedCode, Line: 1, Title: fmt.Sprintf("The config is larger than %d MiB. A real config is a few KiB", MaxSize>>20)}}
}

// minHidden is the shortest hidden part that counts. The PolinRider loader
// is several KiB. A test fixture or an inline snapshot aligns a short value
// after a long run of spaces.
const minHidden = 200

// lastScript returns the offset of the last script token or campaign
// marker in data, or -1. One pass over a line serves every run on it, so a
// line of many runs costs no more than one.
func lastScript(data []byte) int {
	last := -1
	for _, loc := range scriptToken.FindAllIndex(data, -1) {
		last = max(last, loc[0])
	}
	for _, c := range campaigns {
		for _, m := range c.markers {
			for _, loc := range m.FindAllIndex(data, -1) {
				last = max(last, loc[0])
			}
		}
	}
	return last
}

// paddedScript finds a run of white space on a line that a hidden script
// follows: at least minHidden bytes with a script token or a campaign
// marker. A line can align a short value after one run and hide a script
// after the next one, so it checks each run.
func paddedScript(line []byte, n int) (Signal, bool) {
	script := -2
	for off := 0; off < len(line); {
		start, end, count, ok := padRun(line[off:])
		if !ok {
			break
		}
		start, end = off+start, off+end
		if script == -2 {
			script = lastScript(line)
		}
		if len(line)-end >= minHidden && script >= end {
			return Signal{
				ID: IDPaddedCode, Line: n, Visible: finding.Shorten(string(bytes.TrimSpace(line[:start])), maxVisible),
				Title: fmt.Sprintf("Code continues on line %d after %d spaces, with %d bytes off screen", n, count, len(line)-end),
			}, true
		}
		off = end
	}
	return Signal{}, false
}

// padded finds a script that a file hides after a long run of white space,
// or, when exports is true, after the export of a config.
func padded(data []byte, exports bool) []Signal {
	var out []Signal
	for i, line := range bytes.Split(data, []byte("\n")) {
		if s, ok := paddedScript(line, i+1); ok {
			out = append(out, s)
			continue
		}
		if !exports {
			continue
		}
		loc := afterExport.FindIndex(line)
		if loc == nil {
			continue
		}
		rest := bytes.TrimRight(line[loc[1]:], " \t\r")
		if moreExport.Match(rest) || len(rest) < minHidden || lastScript(rest) < 0 {
			continue
		}
		out = append(out, Signal{
			ID: IDPaddedCode, Line: i + 1, Visible: finding.Shorten(string(bytes.TrimSpace(line[:loc[1]])), maxVisible),
			Title: fmt.Sprintf("Code continues on line %d after the export of the config, with %d bytes", i+1, len(rest)),
		})
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
	case unicode.Is(unicode.Cf, r), r == 0x3164, r == 0x115F, r == 0x1160, r == 0xFFA0:
		// A mark such as U+200E or a soft hyphen shows as nothing, so it
		// cannot be the base of a selector.
		return zeroWidth
	}
	return visible
}

const (
	// minRun is the shortest run of invisible characters that hides text.
	// An emoji sequence uses at most two in a row.
	minRun = 4
	// minPayload is the fewest selectors with no base character, or tags
	// outside a flag emoji, that carry a payload. Real text has none.
	minPayload = 16
	// blackFlag starts a subdivision flag emoji, such as the flag of
	// England, which spells its region in tag characters.
	blackFlag = 0x1F3F4
	cancelTag = 0xE007F
)

// decoder is a sign of code that turns invisible characters into a payload.
// It only words the title: the payload itself is the sign.
var decoder = regexp.MustCompile(`(?i)codePointAt|fromCodePoint|charCodeAt|0xfe0[0f]|0xe01[0-9a-f]{2}|\\u\{e01`)

// keycap follows the selector of a keycap emoji, such as 1, a selector and
// the keycap.
const keycap = 0x20E3

// invisible finds a payload in variation selectors or tag characters, a run
// of invisible characters, and a bidi control in code. A selector modifies
// the character before it, such as an emoji or a Han character. A selector
// after ASCII, a space or another invisible character modifies nothing, so
// vet counts it as payload, and so a tag character outside a flag emoji.
// The count covers the whole file, so a decoy run, spaces between the
// characters or one character per line do not hide the payload. An agent
// instruction file can hold right to left text, so only a run counts
// there. A built file gives only the payload signal.
func invisible(p string, data []byte) []Signal {
	if !mayHoldInvisible(data) {
		return nil
	}
	t, isAgentFile := agentfiles.Classify(p)
	code := !isAgentFile || t != agentfiles.Instructions
	built := generated(p)
	var longestLine, longest, bidiLine, payload, payloadLine int
	line, start, cur := 1, 0, 0
	prev := '\n'
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
		switch {
		case k == selector && (prev < utf8.RuneSelf || kindOf(prev) != visible || space(prev)):
			if next, _ := utf8.DecodeRune(data[i:]); next != keycap {
				payload++
			}
		case k == tag:
			payload++
		}
		if payload > 0 && payloadLine == 0 {
			payloadLine = line
		}
		if k == visible {
			if cur > longest {
				longestLine, longest = start, cur
			}
			cur = 0
			if r == '\n' {
				line++
			}
		} else {
			if cur == 0 {
				start = line
			}
			cur++
			if k == bidi && code && bidiLine == 0 {
				bidiLine = line
			}
		}
		prev = r
	}
	if cur > longest {
		longestLine, longest = start, cur
	}
	var out []Signal
	if payload >= minPayload {
		title := fmt.Sprintf("The file hides a payload in %d invisible characters, from line %d", payload, payloadLine)
		if decoder.Match(data) {
			title += ", and holds a decoder"
		}
		return append(out, Signal{ID: IDUnicodePayload, Line: payloadLine, Title: title, Visible: visibleLine(data, payloadLine)})
	}
	if built {
		return nil
	}
	if longest >= minRun {
		out = append(out, Signal{
			ID: IDInvisibleUnicode, Line: longestLine, Visible: visibleLine(data, longestLine),
			Title: fmt.Sprintf("Line %d holds a run of %d invisible characters", longestLine, longest),
		})
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
	return finding.Shorten(l, maxVisible)
}

// maxVisible is the longest visible text of a signal, in runes.
const maxVisible = 200
