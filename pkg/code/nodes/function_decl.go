package nodes

import (
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
)

type CSTFunctionNode struct {
	cst *CST

	// The function declaration
	declaration *sitter.Node

	// Container node, such as a class or a module
	container *sitter.Node

	// Name of the function
	name *sitter.Node

	// Arguments of the function
	args *sitter.Node

	// Body of the function
	body *sitter.Node
}

func NewCSTFunctionNode(cst *CST) *CSTFunctionNode {
	return &CSTFunctionNode{cst: cst}
}

func (n *CSTFunctionNode) WithDeclaration(declaration *sitter.Node) *CSTFunctionNode {
	n.declaration = declaration
	return n
}

func (n *CSTFunctionNode) WithContainer(container *sitter.Node) *CSTFunctionNode {
	n.container = container
	return n
}

func (n *CSTFunctionNode) WithName(name *sitter.Node) *CSTFunctionNode {
	n.name = name
	return n
}

func (n *CSTFunctionNode) WithArgs(args *sitter.Node) *CSTFunctionNode {
	n.args = args
	return n
}

func (n *CSTFunctionNode) WithBody(body *sitter.Node) *CSTFunctionNode {
	n.body = body
	return n
}

func (n *CSTFunctionNode) Declaration() *sitter.Node {
	return n.declaration
}

func (n *CSTFunctionNode) ContainerNode() *sitter.Node {
	return n.container
}

func (n *CSTFunctionNode) NameNode() *sitter.Node {
	return n.name
}

// Human readable Id for use in graph query
func (n CSTFunctionNode) Id() string {
	return fmt.Sprintf("%s/%s", n.Container(), n.Name())
}

func (n CSTFunctionNode) Name() string {
	if n.name != nil {
		return n.name.Content(n.cst.code)
	}

	return ""
}

func (n CSTFunctionNode) Container() string {
	if n.container != nil {
		return n.container.Content(n.cst.code)
	}

	return ""
}
