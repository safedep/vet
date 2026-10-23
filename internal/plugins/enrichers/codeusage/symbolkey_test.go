package codeusage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSymbolKey(t *testing.T) {
	cases := []struct{ language, module, name, want string }{
		{"go", "golang.org/x/net", "golang.org/x/net/html.Render", "golang.org//x//net//html//Render"},
		{"go", "golang.org/x/net", "golang.org/x/net/html.Tokenizer.Next", "golang.org//x//net//html//Tokenizer//Next"},
		{"go", "stdlib", "net/http.ServeContent", "net//http//ServeContent"},
		{"go", "stdlib", "fmt.Println", "fmt//Println"},
		{"go", "github.com/gin-gonic/gin", "github.com/gin-gonic/gin.Default", "github.com//gin-gonic//gin//Default"},
		{"go", "gopkg.in/yaml.v3", "gopkg.in/yaml.v3.Unmarshal", "gopkg.in//yaml.v3//Unmarshal"},
		{"go", "gopkg.in/yaml.v3", "gopkg.in/yaml.v3.Decoder.Decode", "gopkg.in//yaml.v3//Decoder//Decode"},
		{"go", "gopkg.in/src-d/go-git.v4", "gopkg.in/src-d/go-git.v4/plumbing.NewHash", "gopkg.in//src-d//go-git.v4//plumbing//NewHash"},
		{"go", "", "example.com/mod/v2", ""},
		{"rust", "time", "time::OffsetDateTime::now_local", "time//OffsetDateTime//now_local"},
		{"rust", "tokio-util", "tokio-util::codec::Framed::new", "tokio_util//codec//Framed//new"},
		{"rust", "time", "time", ""},
		{"python", "pyyaml", "yaml.load", ""},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, SymbolKey(c.language, c.module, c.name), c.name)
	}
}
