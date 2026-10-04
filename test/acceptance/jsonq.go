package acceptance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/safedep/vet/v2/report"
)

// cmdJSONQ asserts one field of a JSON document or of a JSON line:
// jsonq <file|stdout> <query> <want>. A query is a dotted path. A number
// indexes an array, and a negative number counts from the end. "len" gives
// the length of an array or an object. A file with more than one JSON
// value is an array of its lines. A string compares without its quotes,
// and any other value compares as JSON.
func cmdJSONQ(ts *testscript.TestScript, neg bool, args []string) {
	if len(args) != 3 {
		ts.Fatalf("usage: jsonq <file|stdout> <query> <want>")
	}
	v, err := decodeJSONValues([]byte(ts.ReadFile(args[0])))
	ts.Check(err)
	got, err := query(v, args[1])
	if err != nil {
		if neg {
			return
		}
		ts.Fatalf("jsonq %s: %v", args[1], err)
	}
	if (got == args[2]) == neg {
		ts.Fatalf("jsonq %s: got %s, want %s%s", args[1], got, map[bool]string{true: "not ", false: ""}[neg], args[2])
	}
}

// decodeJSONValues returns the one JSON value of data, or an array of the
// values of a JSON lines file.
func decodeJSONValues(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var vals []any
	for dec.More() {
		var v any
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		vals = append(vals, v)
	}
	switch len(vals) {
	case 0:
		return nil, fmt.Errorf("no JSON value")
	case 1:
		return vals[0], nil
	}
	return vals, nil
}

func query(v any, q string) (string, error) {
	q = strings.TrimPrefix(q, ".")
	if q != "" {
		for _, seg := range strings.Split(q, ".") {
			switch cur := v.(type) {
			case map[string]any:
				if seg == "len" {
					v = json.Number(strconv.Itoa(len(cur)))
					continue
				}
				next, ok := cur[seg]
				if !ok {
					return "", fmt.Errorf("no key %q", seg)
				}
				v = next
			case []any:
				if seg == "len" {
					v = json.Number(strconv.Itoa(len(cur)))
					continue
				}
				i, err := strconv.Atoi(seg)
				if err != nil {
					return "", fmt.Errorf("%q is not an index", seg)
				}
				if i < 0 {
					i += len(cur)
				}
				if i < 0 || i >= len(cur) {
					return "", fmt.Errorf("index %s is out of range", seg)
				}
				v = cur[i]
			default:
				return "", fmt.Errorf("cannot query %q in a scalar", seg)
			}
		}
	}
	if s, ok := v.(string); ok {
		return s, nil
	}
	b, err := json.Marshal(v)
	return string(b), err
}

// cmdReportCheck decodes a report from -o json or -o jsonl and checks its
// framing: reportcheck <file|stdout>. It sets RECORDS to the number of
// records.
func cmdReportCheck(ts *testscript.TestScript, neg bool, args []string) {
	if len(args) != 1 {
		ts.Fatalf("usage: reportcheck <file|stdout>")
	}
	doc, err := report.Read(strings.NewReader(ts.ReadFile(args[0])))
	if neg {
		if err == nil {
			ts.Fatalf("reportcheck: %s is a valid report", args[0])
		}
		return
	}
	ts.Check(err)
	ts.Setenv("RECORDS", strconv.Itoa(len(doc.Records)))
}
