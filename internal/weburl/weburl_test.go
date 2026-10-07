package weburl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValid(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://wiki.example.com/security", true},
		{"http://wiki.example.com", true},
		{"javascript:alert(1)", false},
		{"/security", false},
		{"https://", false},
		{"ftp://example.com", false},
		{"https://good.example@evil.example/", false},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			assert.Equal(t, tc.want, Valid(tc.url))
		})
	}
}
