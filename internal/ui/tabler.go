package ui

import (
	"os"

	"github.com/jedib0t/go-pretty/v6/table"
)

type TablerConfig struct {
	CsvPath              string
	MarkdownPath         string
	SkipStdoutMirror     bool
	SkipAutoAddSeperator bool
}

type tabler struct {
	table  table.Writer
	config TablerConfig
}

func NewTabler(config TablerConfig) *tabler {
	tbl := table.NewWriter()

	if !config.SkipStdoutMirror {
		tbl.SetOutputMirror(os.Stdout)
	}

	return &tabler{
		table:  tbl,
		config: config,
	}
}

func (t *tabler) AddHeader(header ...interface{}) {
	t.table.AppendHeader(header)
	t.checkAddSeparator()
}

func (t *tabler) AddRow(row ...interface{}) {
	t.table.AppendRow(row)
	t.checkAddSeparator()
}

func (t *tabler) checkAddSeparator() {
	if !t.config.SkipAutoAddSeperator {
		t.table.AppendSeparator()
	}
}

func (t *tabler) Finish() error {
	if t.config.CsvPath != "" {
		if err := t.renderCsvFile(t.config.CsvPath); err != nil {
			return err
		}
	}

	if t.config.MarkdownPath != "" {
		if err := t.renderMarkdownFile(t.config.MarkdownPath); err != nil {
			return err
		}
	}

	t.table.Render()
	return nil
}

func (t *tabler) renderCsvFile(path string) error {
	return nil
}

func (t *tabler) renderMarkdownFile(path string) error {
	return nil
}
