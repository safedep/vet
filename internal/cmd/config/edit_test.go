package config

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/v2/internal/app"
)

func TestEditor(t *testing.T) {
	fallback := "vi"
	if runtime.GOOS == "windows" {
		fallback = "notepad"
	}
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"visual wins", map[string]string{"VISUAL": "code --wait", "EDITOR": "nano"}, "code --wait"},
		{"editor", map[string]string{"EDITOR": "nano"}, "nano"},
		{"blank visual", map[string]string{"VISUAL": "  ", "EDITOR": "nano"}, "nano"},
		{"none", nil, fallback},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := app.New(app.Options{LookupEnv: func(k string) (string, bool) {
				v, ok := tc.env[k]
				return v, ok
			}})
			assert.Equal(t, tc.want, editor(a))
		})
	}
}
