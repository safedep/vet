package cloud

import (
	"errors"
	"sort"

	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/cloud/query"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/spf13/cobra"
)

var (
	querySql      string
	queryPageSize int
)

func newQueryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query risks by executing SQL queries",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newQuerySchemaCommand())
	cmd.AddCommand(newQueryExecuteCommand())

	return cmd
}

func newQuerySchemaCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schema",
		Short: "Get the schema for the query service",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := getQuerySchema()
			if err != nil {
				logger.Errorf("Failed to get query schema: %v", err)
			}

			return nil
		},
	}

	return cmd
}

func newQueryExecuteCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "execute",
		Short: "Execute a query",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeQuery()
			if err != nil {
				logger.Errorf("Failed to execute query: %v", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&querySql, "sql", "s", "", "SQL query to execute")
	cmd.Flags().IntVarP(&queryPageSize, "limit", "", 100, "Limit the number of results returned")

	return cmd
}

func getQuerySchema() error {
	client, err := auth.ControlPlaneClientConnection("vet-cloud-query")
	if err != nil {
		return err
	}

	queryService, err := query.NewQueryService(client)
	if err != nil {
		return err
	}

	response, err := queryService.GetSchema()
	if err != nil {
		return err
	}

	tbl := ui.NewTabler(ui.TablerConfig{
		CsvPath:      outputCSV,
		MarkdownPath: outputMarkdown,
	})

	tbl.AddHeader("Name", "Column Name", "Selectable", "Filterable", "Reference")

	schemas := response.GetSchemas()
	for _, schema := range schemas {
		schemaName := schema.GetName()
		columns := schema.GetColumns()

		sort.Slice(columns, func(i, j int) bool {
			return columns[i].GetName() < columns[j].GetName()
		})

		for _, column := range columns {
			tbl.AddRow(schemaName,
				column.GetName(),
				column.GetSelectable(),
				column.GetFilterable(),
				column.GetReferenceUrl())
		}
	}

	return tbl.Finish()
}

func executeQuery() error {
	if querySql == "" {
		return errors.New("SQL string is required")
	}

	client, err := auth.ControlPlaneClientConnection("vet-cloud-query")
	if err != nil {
		return err
	}

	queryService, err := query.NewQueryService(client)
	if err != nil {
		return err
	}

	response, err := queryService.ExecuteSql(querySql, queryPageSize)
	if err != nil {
		return err
	}

	return renderQueryResponseAsTable(response)
}

func renderQueryResponseAsTable(response *query.QueryResponse) error {
	tbl := ui.NewTabler(ui.TablerConfig{
		CsvPath:      outputCSV,
		MarkdownPath: outputMarkdown,
	})

	if response.Count() == 0 {
		logger.Infof("No results found")
		return nil
	}

	ui.PrintSuccess("Query returned %d results", response.Count())

	// Header
	headers := []string{}
	response.GetRow(0).ForEachField(func(key string, _ interface{}) {
		headers = append(headers, key)
	})

	sort.Strings(headers)

	headerRow := []interface{}{}
	for _, header := range headers {
		headerRow = append(headerRow, header)
	}

	tbl.AddHeader(headerRow...)

	// Ensure we have a consistent order of columns
	response.ForEachRow(func(row *query.QueryRow) {
		rowValues := []interface{}{}
		for _, header := range headers {
			rowValues = append(rowValues, row.GetField(header))
		}

		tbl.AddRow(rowValues...)
	})

	return tbl.Finish()
}
