package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultModelsMap(t *testing.T) {
	t.Run("default model map must have vendor, model, and fast model", func(t *testing.T) {
		for vendor, models := range defaultModelMap {
			assert.NotEmpty(t, vendor)
			assert.NotEmpty(t, models["default"])
			assert.NotEmpty(t, models["fast"])
		}
	})
}
