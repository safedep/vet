package tools

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	_ "github.com/mattn/go-sqlite3"

	"github.com/safedep/vet/mcp"
)

type vetSqlQueryTool struct {
	dbPath string
	db     *sql.DB
}

var _ mcp.McpTool = &vetSqlQueryTool{}

// Models for responding to LLM
type tableSchema struct {
	TableName string   `json:"table_name"`
	Columns   []column `json:"columns"`
}

type column struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	NotNull    bool   `json:"not_null"`
	PrimaryKey bool   `json:"primary_key"`
}

type schemaIntrospectionResponse struct {
	Tables []tableSchema `json:"tables"`
}

type queryResult struct {
	Columns []string        `json:"columns"`
	Rows    [][]interface{} `json:"rows"`
	Count   int             `json:"count"`
}

type sqlQueryResponse struct {
	Success bool        `json:"success"`
	Result  queryResult `json:"result,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// NewVetSQLQueryTool creates a new vet SQL query tool. The purpose of this tool
// is to provide agents access to vet SQLite3 report data through SQL queries.
func NewVetSQLQueryTool(dbPath string) (*vetSqlQueryTool, error) {
	// We need the ability to directly execute sqlite3 query without ORM, hence we are skipping
	// the storage interface here. In future, if we need to decouple the storage, we should
	// pass an *sql.DB to the tool.
	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=ro&cache=private&_fk=1", dbPath))
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &vetSqlQueryTool{
		dbPath: dbPath,
		db:     db,
	}, nil
}

func (t *vetSqlQueryTool) Register(server *server.MCPServer) error {
	schemaIntrospectionTool := mcpgo.NewTool("vet_query_sql_introspect_schema",
		mcpgo.WithDescription("Introspect the SQLite3 database schema to understand available tables and their structure. "+
			"This returns information about all tables, columns, types, and relationships in the vet report database."),
	)

	sqlQueryTool := mcpgo.NewTool("vet_query_execute_sql_query",
		mcpgo.WithDescription("Execute an arbitrary SQL query on the vet SQLite3 report database. "+
			"Supports SELECT queries for data analysis, aggregation, and reporting. "+
			"Use vet_query_sql_introspect_schema first to understand the database structure."),

		mcpgo.WithString("sql", mcpgo.Required(), mcpgo.Description("The SQL query to execute. Only SELECT queries are allowed for security.")),
	)

	server.AddTool(schemaIntrospectionTool, t.executeSchemaIntrospection)
	server.AddTool(sqlQueryTool, t.executeSQLQuery)

	return nil
}

func (t *vetSqlQueryTool) executeSchemaIntrospection(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
	// Get all table names
	tablesQuery := `
		SELECT name FROM sqlite_master 
		WHERE type='table' AND name NOT LIKE 'sqlite_%'
		ORDER BY name
	`

	rows, err := t.db.QueryContext(ctx, tablesQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to query tables: %w", err)
	}
	defer rows.Close()

	var tableNames []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			return nil, fmt.Errorf("failed to scan table name: %w", err)
		}
		tableNames = append(tableNames, tableName)
	}

	// Get schema information for each table
	var tables []tableSchema
	for _, tableName := range tableNames {
		schema, err := t.getTableSchema(ctx, t.db, tableName)
		if err != nil {
			return nil, fmt.Errorf("failed to get schema for table %s: %w", tableName, err)
		}

		tables = append(tables, schema)
	}

	response := schemaIntrospectionResponse{
		Tables: tables,
	}

	serializedResponse, err := serializeForLlm(response)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize response: %w", err)
	}

	return mcpgo.NewToolResultText(serializedResponse), nil
}

func (t *vetSqlQueryTool) getTableSchema(ctx context.Context, db *sql.DB, tableName string) (tableSchema, error) {
	pragma := fmt.Sprintf("PRAGMA table_info(%s)", tableName)
	rows, err := db.QueryContext(ctx, pragma)
	if err != nil {
		return tableSchema{}, fmt.Errorf("failed to get table info: %w", err)
	}

	defer rows.Close()

	var columns []column
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, pk int
		var defaultValue sql.NullString

		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err != nil {
			return tableSchema{}, fmt.Errorf("failed to scan column info: %w", err)
		}

		columns = append(columns, column{
			Name:       name,
			Type:       dataType,
			NotNull:    notNull == 1,
			PrimaryKey: pk == 1,
		})
	}

	return tableSchema{
		TableName: tableName,
		Columns:   columns,
	}, nil
}

func (t *vetSqlQueryTool) executeSQLQuery(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
	sqlQuery, err := req.RequireString("sql")
	if err != nil {
		return nil, fmt.Errorf("sql parameter is required: %w", err)
	}

	// Security check: only allow SELECT queries
	normalizedQuery := strings.TrimSpace(strings.ToUpper(sqlQuery))
	if !strings.HasPrefix(normalizedQuery, "SELECT") {
		response := sqlQueryResponse{
			Success: false,
			Error:   "Only SELECT queries are allowed for security reasons",
		}
		serializedResponse, _ := serializeForLlm(response)
		return mcpgo.NewToolResultText(serializedResponse), nil
	}

	rows, err := t.db.QueryContext(ctx, sqlQuery)
	if err != nil {
		response := sqlQueryResponse{
			Success: false,
			Error:   fmt.Sprintf("Query execution failed: %v", err),
		}

		serializedResponse, _ := serializeForLlm(response)
		return mcpgo.NewToolResultText(serializedResponse), nil
	}

	defer rows.Close()

	// Get column names
	columns, err := rows.Columns()
	if err != nil {
		response := sqlQueryResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to get column names: %v", err),
		}
		serializedResponse, _ := serializeForLlm(response)
		return mcpgo.NewToolResultText(serializedResponse), nil
	}

	// Prepare result storage
	var resultRows [][]interface{}
	columnCount := len(columns)

	// Process rows
	for rows.Next() {
		// Create slice to hold column values
		values := make([]interface{}, columnCount)
		valuePtrs := make([]interface{}, columnCount)
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		// Scan row into values
		if err := rows.Scan(valuePtrs...); err != nil {
			response := sqlQueryResponse{
				Success: false,
				Error:   fmt.Sprintf("Failed to scan row: %v", err),
			}
			serializedResponse, _ := serializeForLlm(response)
			return mcpgo.NewToolResultText(serializedResponse), nil
		}

		// Convert byte arrays to strings for JSON serialization
		row := make([]interface{}, columnCount)
		for i, v := range values {
			if b, ok := v.([]byte); ok {
				row[i] = string(b)
			} else {
				row[i] = v
			}
		}

		resultRows = append(resultRows, row)
	}

	if err := rows.Err(); err != nil {
		response := sqlQueryResponse{
			Success: false,
			Error:   fmt.Sprintf("Row iteration error: %v", err),
		}
		serializedResponse, _ := serializeForLlm(response)
		return mcpgo.NewToolResultText(serializedResponse), nil
	}

	response := sqlQueryResponse{
		Success: true,
		Result: queryResult{
			Columns: columns,
			Rows:    resultRows,
			Count:   len(resultRows),
		},
	}

	serializedResponse, err := serializeForLlm(response)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize response: %w", err)
	}

	return mcpgo.NewToolResultText(serializedResponse), nil
}
