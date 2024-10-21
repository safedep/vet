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
	tbl.SetStyle(table.StyleLight)

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

	if !t.config.SkipStdoutMirror {
		if _, err := os.Stdout.WriteString(t.table.Render()); err != nil {
			return err
		}
	}

	return nil
}

func (t *tabler) renderCsvFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}

	defer f.Close()
	_, err = f.WriteString(t.table.RenderCSV())
	if err != nil {
		return err
	}

	return nil
}

func (t *tabler) renderMarkdownFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}

	defer f.Close()
	_, err = f.WriteString(t.table.RenderMarkdown())
	if err != nil {
		return err
	}

	return nil
}
