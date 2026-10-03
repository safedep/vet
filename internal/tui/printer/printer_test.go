package printer

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/tui/output"
)

type item struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func TestPrint(t *testing.T) {
	output.SetMode(output.Plain)
	t.Cleanup(func() { output.SetMode(output.Rich) })

	items := []item{{Name: "a<b", Count: 1}, {Name: "c", Count: 2}}
	rows := Rows{Headers: []string{"NAME", "COUNT"}, Rows: [][]string{{"a<b", "1"}, {"c\td\ne", "2"}}}

	cases := []struct {
		format Format
		value  any
		rows   Rows
		want   string
	}{
		{format: JSON, value: items, want: "[\n  {\n    \"name\": \"a<b\",\n    \"count\": 1\n  },\n  {\n    \"name\": \"c\",\n    \"count\": 2\n  }\n]\n"},
		{format: JSONL, value: items, want: "{\"name\":\"a<b\",\"count\":1}\n{\"name\":\"c\",\"count\":2}\n"},
		{format: JSONL, value: items[0], want: "{\"name\":\"a<b\",\"count\":1}\n"},
		{format: Plain, rows: rows, want: "NAME\tCOUNT\na<b\t1\nc d e\t2\n"},
	}
	for _, tc := range cases {
		t.Run(string(tc.format), func(t *testing.T) {
			var buf bytes.Buffer
			require.NoError(t, New(tc.format, WithWriter(&buf)).Print(tc.value, tc.rows))
			assert.Equal(t, tc.want, buf.String())
		})
	}
}

func TestTable(t *testing.T) {
	output.SetMode(output.Plain)
	t.Cleanup(func() { output.SetMode(output.Rich) })

	var buf bytes.Buffer
	p := New(Table, WithWriter(&buf))
	require.NoError(t, p.Print(nil, Rows{Headers: []string{"NAME"}, Rows: [][]string{{"vet"}}}))
	assert.Contains(t, buf.String(), "NAME")
	assert.Contains(t, buf.String(), "vet")

	buf.Reset()
	require.NoError(t, p.Print(nil, Rows{Headers: []string{"NAME"}, Empty: "No scans."}))
	assert.Contains(t, buf.String(), "No scans.")
}

func TestParseAndDefaultFormat(t *testing.T) {
	for _, f := range Formats() {
		got, err := ParseFormat(string(f))
		require.NoError(t, err)
		assert.Equal(t, f, got)
	}
	_, err := ParseFormat("xml")
	assert.Error(t, err)

	assert.Equal(t, Table, DefaultFormat(output.Rich))
	assert.Equal(t, Plain, DefaultFormat(output.Plain))
	assert.Equal(t, JSON, DefaultFormat(output.Agent))
}

func TestPrintText(t *testing.T) {
	value := item{Name: "vet", Count: 1}
	cases := []struct {
		format Format
		want   string
	}{
		{format: Table, want: "vet 1\nsecond\n"},
		{format: Plain, want: "vet 1\nsecond\n"},
		{format: JSON, want: "{\n  \"name\": \"vet\",\n  \"count\": 1\n}\n"},
		{format: JSONL, want: "{\"name\":\"vet\",\"count\":1}\n"},
	}
	for _, tc := range cases {
		t.Run(string(tc.format), func(t *testing.T) {
			var buf bytes.Buffer
			require.NoError(t, New(tc.format, WithWriter(&buf)).PrintText(value, "vet 1", "second"))
			assert.Equal(t, tc.want, buf.String())
		})
	}
}
