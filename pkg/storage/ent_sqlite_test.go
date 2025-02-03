package storage

import (
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
	})
}
