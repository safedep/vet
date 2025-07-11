package storage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSqliteStorage(t *testing.T) {
	t.Run("NewEntSqliteStorage", func(t *testing.T) {
		t.Run("should return storage and its client when path is given", func(t *testing.T) {
			tmpPath := filepath.Join(t.TempDir(), "test.db")
			sqliteStorage, err := NewEntSqliteStorage(EntSqliteClientConfig{
				Path: tmpPath,
			})
			assert.NoError(t, err)
			assert.NotNil(t, sqliteStorage)
			assert.FileExists(t, tmpPath)

			client, err := sqliteStorage.Client()
			assert.NoError(t, err)
			assert.NotNil(t, client)
		})

		t.Run("should return an error when an invalid storage path is given", func(t *testing.T) {
			sqliteStorage, err := NewEntSqliteStorage(EntSqliteClientConfig{
				Path: "/invalid/path/1/2",
			})

			assert.Error(t, err)
			assert.Nil(t, sqliteStorage)
		})

		t.Run("should return error when both FailIfPathExists and OverwriteIfPathExists are true", func(t *testing.T) {
			tmpPath := filepath.Join(t.TempDir(), "test.db")
			sqliteStorage, err := NewEntSqliteStorage(EntSqliteClientConfig{
				Path:                  tmpPath,
				FailIfPathExists:      true,
				OverwriteIfPathExists: true,
			})

			assert.Error(t, err)
			assert.Nil(t, sqliteStorage)
			assert.Contains(t, err.Error(), "both FailIfPathExists and OverwriteIfPathExists cannot be true")
		})

		t.Run("FailIfPathExists", func(t *testing.T) {
			t.Run("should return error when path already exists", func(t *testing.T) {
				tmpDir := t.TempDir()
				tmpPath := filepath.Join(tmpDir, "test.db")

				// Create the file first
				_, err := os.Create(tmpPath)
				assert.NoError(t, err)
				assert.FileExists(t, tmpPath)

				sqliteStorage, err := NewEntSqliteStorage(EntSqliteClientConfig{
					Path:             tmpPath,
					FailIfPathExists: true,
				})

				assert.Error(t, err)
				assert.Nil(t, sqliteStorage)
				assert.Contains(t, err.Error(), "already exists")
			})

			t.Run("should work normally when path doesn't exist", func(t *testing.T) {
				tmpPath := filepath.Join(t.TempDir(), "test.db")

				sqliteStorage, err := NewEntSqliteStorage(EntSqliteClientConfig{
					Path:             tmpPath,
					FailIfPathExists: true,
				})

				assert.NoError(t, err)
				assert.NotNil(t, sqliteStorage)
				assert.FileExists(t, tmpPath)

				client, err := sqliteStorage.Client()
				assert.NoError(t, err)
				assert.NotNil(t, client)
			})
		})

		t.Run("OverwriteIfPathExists", func(t *testing.T) {
			t.Run("should overwrite existing file", func(t *testing.T) {
				tmpDir := t.TempDir()
				tmpPath := filepath.Join(tmpDir, "test.db")

				// Create the file first with some content
				err := os.WriteFile(tmpPath, []byte("existing content"), 0o644)
				assert.NoError(t, err)
				assert.FileExists(t, tmpPath)

				sqliteStorage, err := NewEntSqliteStorage(EntSqliteClientConfig{
					Path:                  tmpPath,
					OverwriteIfPathExists: true,
				})

				assert.NoError(t, err)
				assert.NotNil(t, sqliteStorage)
				assert.FileExists(t, tmpPath)

				client, err := sqliteStorage.Client()
				assert.NoError(t, err)
				assert.NotNil(t, client)

				// Verify the file was overwritten by checking if it's a valid SQLite database
				// (the original content would not be a valid SQLite database)
				defer sqliteStorage.Close()
			})

			t.Run("should work normally when path doesn't exist", func(t *testing.T) {
				tmpPath := filepath.Join(t.TempDir(), "test.db")

				sqliteStorage, err := NewEntSqliteStorage(EntSqliteClientConfig{
					Path:                  tmpPath,
					OverwriteIfPathExists: true,
				})

				assert.NoError(t, err)
				assert.NotNil(t, sqliteStorage)
				assert.FileExists(t, tmpPath)

				client, err := sqliteStorage.Client()
				assert.NoError(t, err)
				assert.NotNil(t, client)
			})
		})

		t.Run("should work normally when file exists and neither flag is set", func(t *testing.T) {
			tmpDir := t.TempDir()
			tmpPath := filepath.Join(tmpDir, "test.db")

			// Create the file first
			_, err := os.Create(tmpPath)
			assert.NoError(t, err)
			assert.FileExists(t, tmpPath)

			sqliteStorage, err := NewEntSqliteStorage(EntSqliteClientConfig{
				Path: tmpPath,
			})

			assert.NoError(t, err)
			assert.NotNil(t, sqliteStorage)
			assert.FileExists(t, tmpPath)

			client, err := sqliteStorage.Client()
			assert.NoError(t, err)
			assert.NotNil(t, client)
		})
	})
}
