package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
)

func lines(t *testing.T, ls ...Line) string {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	for _, l := range ls {
		require.NoError(t, enc.Encode(l))
	}
	return b.String()
}

func TestRead(t *testing.T) {
	h := &Header{SchemaVersion: SchemaVersion}
	m := ManifestRecord(&model.Manifest{ID: "m1", Path: "go.mod"})
	ok := &Trailer{RecordCount: 1}
	bad := &Trailer{RecordCount: 2}

	doc, err := json.Marshal(Document{Header: *h, Records: []Record{m}, Trailer: *ok})
	require.NoError(t, err)

	cases := []struct {
		name    string
		in      string
		records int
		wantErr bool
	}{
		{name: "jsonl", in: lines(t, HeaderLine(h), RecordLine(m), TrailerLine(ok)), records: 1},
		{name: "json document", in: string(doc), records: 1},
		{name: "count mismatch", in: lines(t, HeaderLine(h), RecordLine(m), TrailerLine(bad)), wantErr: true},
		{name: "no header", in: lines(t, RecordLine(m), TrailerLine(ok)), wantErr: true},
		{name: "no trailer", in: lines(t, HeaderLine(h), RecordLine(m)), wantErr: true},
		{name: "line after trailer", in: lines(t, HeaderLine(h), TrailerLine(&Trailer{}), RecordLine(m)), wantErr: true},
		{name: "header not first", in: lines(t, HeaderLine(h), HeaderLine(h), TrailerLine(&Trailer{})), wantErr: true},
		{name: "no schema", in: `{"kind":"header","header":{}}` + "\n", wantErr: true},
		{name: "json document without trailer", in: `{"header":{},"records":[]}`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Read(strings.NewReader(tc.in))
			if tc.wantErr {
				assert.ErrorIs(t, err, ErrFraming)
				return
			}
			require.NoError(t, err)
			assert.Len(t, got.Records, tc.records)
			assert.Equal(t, SchemaVersion, got.Header.SchemaVersion)
		})
	}
}

func TestLineCarriesSchemaAndKind(t *testing.T) {
	b, err := json.Marshal(HeaderLine(&Header{}))
	require.NoError(t, err)
	assert.Contains(t, string(b), `"$schema":"`+SchemaURL+`"`)
	assert.Contains(t, string(b), `"kind":"header"`)
}
