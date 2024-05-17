package code

import sitter "github.com/smacker/go-tree-sitter"

// Tree Sitter utils for the code analysis framework

type tsQueryMatchHandler func(*sitter.QueryMatch, *sitter.Query, bool) error

func tsExecQuery(query string, lang *sitter.Language, source []byte,
	node *sitter.Node, handler tsQueryMatchHandler) error {
	tsQuery, err := sitter.NewQuery([]byte(query), lang)
	if err != nil {
		return err
	}

	tsQueryCursor := sitter.NewQueryCursor()
	tsQueryCursor.Exec(tsQuery, node)

	for {
		match, ok := tsQueryCursor.NextMatch()
		if !ok {
			break
		}

		match = tsQueryCursor.FilterPredicates(match, source)

		if len(match.Captures) == 0 {
			continue
		}

		if err := handler(match, tsQuery, ok); err != nil {
			return err
		}
	}

	return nil
}
