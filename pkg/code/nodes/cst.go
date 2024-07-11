package nodes

import (
	"context"

	sitter "github.com/smacker/go-tree-sitter"
)

// Represents a Concreate Syntax Tree (CST) of a *single* source file
// We will use TreeSitter as the only supported parser.
// However, we can have language specific wrappers over TreeSitter CST
// to make it easy for high level modules to operate
type CST struct {
	tree *sitter.Tree
	lang *sitter.Language
	code []byte
}

func NewCST(tree *sitter.Tree, lang *sitter.Language, code []byte) *CST {
	return &CST{tree: tree, lang: lang, code: code}
}

func (n *CST) Close() {
	n.tree.Close()
}

func (n *CST) Root() *sitter.Node {
	return n.tree.RootNode()
}

func (n *CST) Code() []byte {
	return n.code
}

func (n *CST) SubTree(node *sitter.Node) (*CST, error) {
	p := sitter.NewParser()
	p.SetLanguage(n.lang)

	data := []byte(node.Content(n.code))

	t, err := p.ParseCtx(context.Background(), nil, data)
	if err != nil {
		return nil, err
	}

	return NewCST(t, n.lang, data), nil
}
