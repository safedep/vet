package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

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

	// Fail if path already exists
	FailIfPathExists bool

	// Overwrite if path already exists
	OverwriteIfPathExists bool
}

type entSqliteClient struct {
	client *ent.Client
}

func NewEntSqliteStorage(config EntSqliteClientConfig) (Storage[*ent.Client], error) {
	if config.FailIfPathExists && config.OverwriteIfPathExists {
		return nil, fmt.Errorf("both FailIfPathExists and OverwriteIfPathExists cannot be true")
	}

	// Ensure the directory exists
	dir := filepath.Dir(config.Path)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return nil, fmt.Errorf("failed to create DB path %s: %w", dir, err)
	}

	if _, err := os.Stat(config.Path); err == nil {
		// Always fail fast if the path already exists to be safe and defensive
		if config.FailIfPathExists {
			return nil, fmt.Errorf("path %s already exists", config.Path)
		}

		if config.OverwriteIfPathExists {
			if err := os.Remove(config.Path); err != nil {
				return nil, fmt.Errorf("failed to remove existing file %s: %w", config.Path, err)
			}
		}
	}

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
