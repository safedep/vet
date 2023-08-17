package py 

import (
	"fmt"
	"os"
	"strings"
	// "github.com/mpvl/unique"
	"github.com/safedep/vet/pkg/common/logger"
	treesitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"
)

// SetuppyParserViaSyntaxTree holds the parsing and extraction logic for setup.py files.
type SetuppyParserViaSyntaxTree struct
{
	Symbol2strings map[string][]string
	Symbol2symbols map[string][]string
	Parser *treesitter.Parser
}

// NewSetuppyParserViaSyntaxTree creates a new instance of SetuppyParserViaSyntaxTree.
func NewSetuppyParserViaSyntaxTree() *SetuppyParserViaSyntaxTree {
	s := &SetuppyParserViaSyntaxTree{}
	s.Symbol2strings = make(map[string][]string, 0)
	s.Symbol2symbols = make(map[string][]string, 0)
	s.Parser = treesitter.NewParser()
	s.Parser.SetLanguage(python.GetLanguage())
	return s
}

// extractStringConstants recursively extracts string constants and symbols from the syntax tree nodes.
func (s *SetuppyParserViaSyntaxTree) extractStringConstants(node *treesitter.Node, code []byte) ([]string, []string) {
	const_strings := []string{}
	symbol_string := []string{}
	// fmt.Println(" - ", string(node.Content(code)) )
	// fmt.Println(node.ChildCount() , node.Type())
	switch node.Type() {
	case "identifier":
		for i := uint32(0); i < node.ChildCount(); i++ {
			child := node.Child(int(i))
			a, b := s.extractStringConstants(child, code)
			const_strings = append(const_strings, a...)
			symbol_string = append(symbol_string, b...)
		}
		symbol_string = append(symbol_string, node.Content(code))
	case "function_definition":
		if node.Child(0).Type() == "def" &&  node.Child(1).Type() == "identifier"{
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
	case "string":
		a := strings.Trim(string(node.Content(code)), "\"")
		const_strings = append(const_strings, a)
	case "assignment":
		attribute := node.Child(0)
		if attribute.Type() == "identifier" {
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
	case "format_string":
		a, b := s.extractStringConstants(node.Child(0), code)
		const_strings = append(const_strings, a...)
		symbol_string = append(symbol_string, b...)
	case "expr_list", "testlist":
		for i := uint32(0); i < node.ChildCount(); i++ {
			child := node.Child(int(i))
			a, b := s.extractStringConstants(child, code)
			const_strings = append(const_strings, a...)
			symbol_string = append(symbol_string, b...)
		}
	case "keyword_argument": {
		attribute := node.Child(0)
		if attribute.Type() == "identifier" {
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
	case "call":
		// fmt.Println(node.ChildCount() , node.Child(0).Type(), node.Child(0).Content(code))
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
func (s *SetuppyParserViaSyntaxTree) aggStringConstants(src string) []string {
	const_strings := []string{}
	dep_syms := []string{}

	if cs, ok := s.Symbol2strings[src]; ok {
		const_strings = append(const_strings, cs...)
	} 

	if ds, ok := s.Symbol2symbols[src]; !ok {
		return const_strings
	} else {
		dep_syms = ds
	}

	for _, sym := range dep_syms {
		a := s.aggStringConstants(sym)
		const_strings = append(const_strings, a...)
	}

	//Remove " char


	//Remvove Duplicates
	// unique.Sort(unique.StringSlice{&const_strings})
	// fmt.Printf("%s", strings.Join(const_strings[:], ","))

	return const_strings
}

/**
 GetDependencyStrings extracts dependency strings from a setup.py file.

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
func (s *SetuppyParserViaSyntaxTree) GetDependencyStrings(filepath string) ([]string, error) {

	var dependencies []string
	var code []byte

	if content, err := os.ReadFile(filepath); err != nil {
		logger.Warnf("Error opening setuppy file %v", err)
		return dependencies, err
	} else {
		code = content
	}

	tree := s.Parser.Parse(nil, code)

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
