package report

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// The kinds of the first and the last line of a jsonl report.
const (
	LineHeader  Kind = "header"
	LineTrailer Kind = "trailer"
)

// Line is one line of "-o jsonl": the header, one record or the trailer.
// Each line carries $schema and kind.
type Line struct {
	Schema string `json:"$schema"`
	Record
	Header  *Header  `json:"header,omitempty"`
	Trailer *Trailer `json:"trailer,omitempty"`
}

// HeaderLine returns the first line of a jsonl report.
func HeaderLine(h *Header) Line {
	return Line{Schema: LineSchemaURL, Record: Record{Kind: LineHeader}, Header: h}
}

// RecordLine returns the line of one record.
func RecordLine(r Record) Line { return Line{Schema: LineSchemaURL, Record: r} }

// TrailerLine returns the last line of a jsonl report.
func TrailerLine(t *Trailer) Line {
	return Line{Schema: LineSchemaURL, Record: Record{Kind: LineTrailer}, Trailer: t}
}

// ErrFraming means that a report stream is not complete or not in order.
var ErrFraming = errors.New("report: bad framing")

// Read decodes a report from "-o json" or "-o jsonl" and checks its
// framing: the header comes first, the trailer comes last, and the record
// count of the trailer equals the number of records.
func Read(r io.Reader) (*Document, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var doc *Document
	if isJSONDocument(data) {
		doc, err = readDocument(data)
	} else {
		doc, err = readLines(data)
	}
	if err != nil {
		return nil, err
	}
	if doc.Trailer.RecordCount != uint64(len(doc.Records)) {
		return nil, fmt.Errorf("%w: record_count is %d, the report has %d records", ErrFraming, doc.Trailer.RecordCount, len(doc.Records))
	}
	return doc, nil
}

// isJSONDocument tells "-o json" from "-o jsonl". A json document has a
// "header" key at the top level, and a jsonl line has "$schema".
func isJSONDocument(data []byte) bool {
	var probe map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&probe); err != nil {
		return false
	}
	_, hasHeader := probe["header"]
	_, hasSchema := probe["$schema"]
	return hasHeader && !hasSchema
}

func readDocument(data []byte) (*Document, error) {
	var raw struct {
		Header  *Header   `json:"header"`
		Records *[]Record `json:"records"`
		Trailer *Trailer  `json:"trailer"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode report: %w", err)
	}
	if raw.Header == nil || raw.Records == nil || raw.Trailer == nil {
		return nil, fmt.Errorf("%w: the document needs header, records and trailer", ErrFraming)
	}
	return &Document{Header: *raw.Header, Records: *raw.Records, Trailer: *raw.Trailer}, nil
}

func readLines(data []byte) (*Document, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 64*1024*1024)
	doc := &Document{Records: []Record{}}
	n, sawHeader, sawTrailer := 0, false, false
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		n++
		var l Line
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			return nil, fmt.Errorf("decode line %d: %w", n, err)
		}
		if l.Schema == "" {
			return nil, fmt.Errorf("%w: line %d has no $schema", ErrFraming, n)
		}
		switch {
		case sawTrailer:
			return nil, fmt.Errorf("%w: line %d comes after the trailer", ErrFraming, n)
		case l.Kind == LineHeader:
			if n != 1 || l.Header == nil {
				return nil, fmt.Errorf("%w: the header must be line 1", ErrFraming)
			}
			doc.Header, sawHeader = *l.Header, true
		case !sawHeader:
			return nil, fmt.Errorf("%w: line 1 is not the header", ErrFraming)
		case l.Kind == LineTrailer:
			if l.Trailer == nil {
				return nil, fmt.Errorf("%w: line %d has no trailer", ErrFraming, n)
			}
			doc.Trailer, sawTrailer = *l.Trailer, true
		default:
			doc.Records = append(doc.Records, l.Record)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !sawTrailer {
		return nil, fmt.Errorf("%w: the report has no trailer", ErrFraming)
	}
	return doc, nil
}
