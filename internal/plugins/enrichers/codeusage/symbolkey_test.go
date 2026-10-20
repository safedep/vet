package codeusage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSymbolKey(t *testing.T) {
	cases := []struct{ language, name, want string }{
		{"go", "golang.org/x/net/html.Render", "golang.org//x//net//html//Render"},
		{"go", "golang.org/x/net/html.Tokenizer.Next", "golang.org//x//net//html//Tokenizer//Next"},
		{"go", "net/http.ServeContent", "net//http//ServeContent"},
		{"go", "fmt.Println", "fmt//Println"},
		{"go", "github.com/gin-gonic/gin.Default", "github.com//gin-gonic//gin//Default"},
		{"go", "example.com/mod/v2", ""},
		{"rust", "time::OffsetDateTime::now_local", "time//OffsetDateTime//now_local"},
		{"rust", "tokio-util::codec::Framed::new", "tokio_util//codec//Framed//new"},
		{"rust", "time", ""},
		{"python", "yaml.load", ""},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, symbolKey(c.language, c.name), c.name)
	}
}
