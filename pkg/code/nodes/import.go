package nodes

import sitter "github.com/smacker/go-tree-sitter"

type CSTImportNode struct {
	cst             *CST
	moduleNameNode  *sitter.Node
	moduleItemNode  *sitter.Node
	moduleAliasNode *sitter.Node
}

func NewCSTImportNode(cst *CST) *CSTImportNode {
	return &CSTImportNode{cst: cst}
}

func (n *CSTImportNode) WithModuleName(moduleName *sitter.Node) *CSTImportNode {
	n.moduleNameNode = moduleName
	return n
}

func (n *CSTImportNode) WithModuleItem(moduleItem *sitter.Node) *CSTImportNode {
	n.moduleItemNode = moduleItem
	return n
}

func (n *CSTImportNode) WithModuleAlias(moduleAlias *sitter.Node) *CSTImportNode {
	n.moduleAliasNode = moduleAlias
	return n
}

func (n CSTImportNode) ImportName() string {
	if n.moduleNameNode != nil {
		return n.moduleNameNode.Content(n.cst.code)
	}

	return ""
}

func (n CSTImportNode) ImportItem() string {
	if n.moduleItemNode != nil {
		return n.moduleItemNode.Content(n.cst.code)
	}

	return ""
}

func (n CSTImportNode) ImportAlias() string {
	if n.moduleAliasNode != nil {
		return n.moduleAliasNode.Content(n.cst.code)
	}

	return ""
}
