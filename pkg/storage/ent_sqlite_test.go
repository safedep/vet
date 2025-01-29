package storage

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSqliteClient(t *testing.T) {
	t.Run("NewEntSqliteClient", func(t *testing.T) {
		t.Run("should return storage client when path is given", func(t *testing.T) {
			tmpPath := filepath.Join(t.TempDir(), "test.db")
			client, err := NewEntSqliteClient(EntSqliteClientConfig{
				Path: tmpPath,
			})

			assert.NoError(t, err)
			assert.NotNil(t, client)
			assert.FileExists(t, tmpPath)
		})

		t.Run("should return an error when an invalid path is given", func(t *testing.T) {
			client, err := NewEntSqliteClient(EntSqliteClientConfig{
				Path: "/invalid/path/1/2",
			})

			assert.Error(t, err)
			assert.Nil(t, client)
		})
	})
}
