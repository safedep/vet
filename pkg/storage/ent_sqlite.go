package storage

import (
	"context"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	"github.com/safedep/vet/ent"
)

type EntSqliteClientConfig struct {
	// Path to the sqlite database file
	Path string

	// Read Only mode
	ReadOnly bool

	// Skip schema creation
	SkipSchemaCreation bool
}

type entSqliteClient struct {
	client *ent.Client
}

func NewEntSqliteClient(config EntSqliteClientConfig) (Storage[*ent.Client], error) {
	mode := "rwc"
	if config.ReadOnly {
		mode = "ro"
	}

	dbConn := fmt.Sprintf("file:%s?mode=%s&cache=private&_fk=1", config.Path, mode)
	client, err := ent.Open("sqlite3", dbConn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite3 connection: %w", err)
	}

	if !config.SkipSchemaCreation {
		if err := client.Schema.Create(context.Background()); err != nil {
			return nil, fmt.Errorf("failed to create schema resources: %w", err)
		}
	}

	return &entSqliteClient{
		client: client,
	}, nil
}

func (c *entSqliteClient) Client() (*ent.Client, error) {
	return c.client, nil
}

func (c *entSqliteClient) Close() error {
	return c.client.Close()
}
