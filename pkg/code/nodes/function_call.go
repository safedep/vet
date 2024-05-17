package nodes

import sitter "github.com/smacker/go-tree-sitter"

type CSTFunctionCallNode struct {
	cst    *CST
	caller *CSTFunctionNode

	call     *sitter.Node
	receiver *sitter.Node
	callee   *sitter.Node
	args     *sitter.Node
}

func NewCSTFunctionCallNode(cst *CST) *CSTFunctionCallNode {
	return &CSTFunctionCallNode{cst: cst}
}

// Should we mutate the receiver or make a copy?
func (n *CSTFunctionCallNode) WithCaller(caller *CSTFunctionNode) *CSTFunctionCallNode {
	n.caller = caller
	return n
}

func (n *CSTFunctionCallNode) WithCall(call *sitter.Node) *CSTFunctionCallNode {
	n.call = call
	return n
}

func (n *CSTFunctionCallNode) WithReceiver(receiver *sitter.Node) *CSTFunctionCallNode {
	n.receiver = receiver
	return n
}

func (n *CSTFunctionCallNode) WithCallee(callee *sitter.Node) *CSTFunctionCallNode {
	n.callee = callee
	return n
}

func (n *CSTFunctionCallNode) WithArgs(args *sitter.Node) *CSTFunctionCallNode {
	n.args = args
	return n
}

func (n CSTFunctionCallNode) CallNode() *sitter.Node {
	return n.call
}

func (n CSTFunctionCallNode) ReceiverNode() *sitter.Node {
	return n.receiver
}

func (n CSTFunctionCallNode) Receiver() string {
	if n.receiver != nil {
		return n.receiver.Content(n.cst.code)
	}

	return ""
}

func (n CSTFunctionCallNode) Callee() string {
	if n.callee != nil {
		return n.callee.Content(n.cst.code)
	}

	return ""
}
