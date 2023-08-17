package py

import (
	"context"
	"fmt"
	"github.com/safedep/vet/pkg/common/logger"
	treesitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"
	"os"
	"strings"
)

const (
	node_type_identifier          = "identifier"
	node_type_function_definition = "function_definition"
	node_type_string              = "string"
	node_type_assignment          = "assignment"
	node_type_format_string       = "format_string"
	node_type_expr_list           = "expr_list"
	node_type_testlist            = "testlist"
	node_type_keyword_argument    = "keyword_argument"
	node_type_call                = "call"
	node_type_def                 = "def"
)

// setuppyParserViaSyntaxTree holds the parsing and extraction logic for setup.py files.
type setuppyParserViaSyntaxTree struct {
	Symbol2strings map[string][]string
	Symbol2symbols map[string][]string
	Parser         *treesitter.Parser
}

// newSetuppyParserViaSyntaxTree creates a new instance of setuppyParserViaSyntaxTree.
func newSetuppyParserViaSyntaxTree() *setuppyParserViaSyntaxTree {
	s := &setuppyParserViaSyntaxTree{}
	s.Symbol2strings = make(map[string][]string, 0)
	s.Symbol2symbols = make(map[string][]string, 0)
	s.Parser = treesitter.NewParser()
	s.Parser.SetLanguage(python.GetLanguage())
	return s
}

// extractStringConstants recursively extracts string constants and symbols from the syntax tree nodes.
func (s *setuppyParserViaSyntaxTree) extractStringConstants(node *treesitter.Node, code []byte) ([]string, []string) {
	const_strings := []string{}
	symbol_string := []string{}
	switch node.Type() {
	case node_type_identifier:
		for i := uint32(0); i < node.ChildCount(); i++ {
			child := node.Child(int(i))
			a, b := s.extractStringConstants(child, code)
			const_strings = append(const_strings, a...)
			symbol_string = append(symbol_string, b...)
		}
		symbol_string = append(symbol_string, node.Content(code))
	case node_type_function_definition:
		if node.Child(0).Type() == node_type_def && node.Child(1).Type() == node_type_identifier {
			const_strings2 := make([]string, 0)
			symbol_strings2 := []string{}
			for i := uint32(2); i < node.ChildCount(); i++ {
				child := node.Child(int(i))
				a, b := s.extractStringConstants(child, code)
				const_strings2 = append(const_strings2, a...)
				symbol_strings2 = append(symbol_strings2, b...)
			}
			const_strings = append(const_strings, const_strings2...)
			symbol_string = append(symbol_string, symbol_strings2...)
			symbol_string = append(symbol_string, node.Child(1).Content(code))
			s.Symbol2strings[node.Child(1).Content(code)] = const_strings2
			s.Symbol2symbols[node.Child(1).Content(code)] = symbol_strings2

		}
	case node_type_string:
		a := strings.Trim(string(node.Content(code)), "\"")
		const_strings = append(const_strings, a)
	case node_type_assignment:
		attribute := node.Child(0)
		if attribute.Type() == node_type_identifier {
			const_strings2 := make([]string, 0)
			symbol_strings2 := []string{}
			for i := uint32(1); i < node.ChildCount(); i++ {
				child := node.Child(int(i))
				a, b := s.extractStringConstants(child, code)
				const_strings2 = append(const_strings2, a...)
				symbol_strings2 = append(symbol_strings2, b...)
			}
			const_strings = append(const_strings, const_strings2...)
			symbol_string = append(symbol_string, symbol_strings2...)
			symbol_string = append(symbol_string, attribute.Content(code))
			s.Symbol2strings[attribute.Content(code)] = const_strings2
			s.Symbol2symbols[attribute.Content(code)] = symbol_strings2

		}
	case node_type_format_string:
		a, b := s.extractStringConstants(node.Child(0), code)
		const_strings = append(const_strings, a...)
		symbol_string = append(symbol_string, b...)
	case node_type_expr_list, node_type_testlist:
		for i := uint32(0); i < node.ChildCount(); i++ {
			child := node.Child(int(i))
			a, b := s.extractStringConstants(child, code)
			const_strings = append(const_strings, a...)
			symbol_string = append(symbol_string, b...)
		}
	case node_type_keyword_argument:
		{
			attribute := node.Child(0)
			if attribute.Type() == node_type_identifier {
				const_strings2 := make([]string, 0)
				symbol_strings2 := make([]string, 0)
				for i := uint32(1); i < node.ChildCount(); i++ {
					child := node.Child(int(i))
					a, b := s.extractStringConstants(child, code)
					const_strings2 = append(const_strings2, a...)
					symbol_strings2 = append(symbol_strings2, b...)
				}
				const_strings = append(const_strings, const_strings2...)
				symbol_string = append(symbol_string, symbol_strings2...)

				s.Symbol2strings[attribute.Content(code)] = const_strings2
				s.Symbol2symbols[attribute.Content(code)] = symbol_strings2
			}
		}
	case node_type_call:
		for i := uint32(0); i < node.ChildCount(); i++ {
			child := node.Child(int(i))
			a, b := s.extractStringConstants(child, code)
			const_strings = append(const_strings, a...)
			symbol_string = append(symbol_string, b...)
		}
	default:
		for i := uint32(0); i < node.ChildCount(); i++ {
			child := node.Child(int(i))
			a, b := s.extractStringConstants(child, code)
			const_strings = append(const_strings, a...)
			symbol_string = append(symbol_string, b...)
		}
	}

	return const_strings, symbol_string
}

// aggStringConstants aggregates string constants based on dependencies.
func (s *setuppyParserViaSyntaxTree) aggStringConstants(src string) []string {
	const_strings := []string{}

	if cs, ok := s.Symbol2strings[src]; ok {
		const_strings = append(const_strings, cs...)
	}

	var dep_syms []string
	if ds, ok := s.Symbol2symbols[src]; !ok {
		return const_strings
	} else {
		dep_syms = ds
	}

	for _, sym := range dep_syms {
		a := s.aggStringConstants(sym)
		const_strings = append(const_strings, a...)
	}

	return const_strings
}

/*
*

	getDependencyStrings extracts dependency strings from a setup.py file.

	- "iptools>=0.7.0"

- "parsedatetime>=2.4"
- "beautifulsoup4>=4.7.1"
- "fuzzywuzzy>=0.18.0"
- "PySocks>=1.7.0"
- "truffleHogRegexes>=0.0.7"
- "soupsieve>=1.9.1"
- "filetype>=1.0.5"
- "pyunpack>=0.1.2"
- "patool>=1.12"
- "wordninja>=2.0.0"
- "iocextract>=1.13.1"
- "pyparsing>=3.0.8"
- "ioc-fanger"
- "titlecase>=0.12.0"
- "furl>=2.1.0"
- "pathlib2>=2.3.3"
- "lxml>=4.5.0"
- "food-exceptions>=0.4.4"
- "food-models>=3.3.1"
- "dateutils>=0.6.6"
- "publicsuffixlist>=0.6.2"
- "dnspython"
- "netaddr>=0.7.18"
- "validators>=0.12.2"
- "fqdn>=1.1.0"
- "tld>=0.9.1"
- "cchardet>=2.1.4"
- "urllib3>=1.22"
- "tldextract>=2.2.0"
*/
func (s *setuppyParserViaSyntaxTree) getDependencyStrings(filepath string) ([]string, error) {

	var dependencies []string
	var code []byte

	if content, err := os.ReadFile(filepath); err != nil {
		logger.Warnf("Error opening setuppy file %v", err)
		return dependencies, err
	} else {
		code = content
	}

	ctx := context.Background()
	tree, err := s.Parser.ParseCtx(ctx, nil, code)

	if err != nil {
		logger.Warnf("Error while creating parser %v", err)
		return dependencies, err
	}

	if tree.RootNode().Type() != "module" {
		return dependencies, fmt.Errorf("Error parsing module")
	}

	s.extractStringConstants(tree.RootNode(), code)
	dependencies = s.aggStringConstants("install_requires")

	logger.Debugf("String Constants in install_requires:")
	for _, constant := range dependencies {
		logger.Debugf("- %s", constant)
	}
	logger.Debugf("Symbol to Constant Strings %v", s.Symbol2strings)
	logger.Debugf("Symbol to Symbols Strings %v", (s.Symbol2symbols))

	return dependencies, nil
}
