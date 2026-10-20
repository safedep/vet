package codeusage

import "strings"

// symbolKey turns the name of a fix site, as a symbol record writes it, into
// the symbol key of safedep/code. A Go name is the import path, a dot and the
// symbol, as golang.org/x/net/html.Tokenizer.Next. A Rust name is a path with
// ::, as time::OffsetDateTime::now_local, and its crate name folds - to _.
// It returns "" for a language that has no rule.
func SymbolKey(language, name string) string {
	switch language {
	case "go":
		pkg, sym := name, ""
		if slash := strings.LastIndex(name, "/"); slash >= 0 {
			if dot := strings.Index(name[slash:], "."); dot >= 0 {
				pkg, sym = name[:slash+dot], name[slash+dot+1:]
			}
		} else if dot := strings.Index(name, "."); dot >= 0 {
			pkg, sym = name[:dot], name[dot+1:]
		}
		if sym == "" {
			return ""
		}
		return strings.ReplaceAll(pkg, "/", keySep) + keySep + strings.ReplaceAll(sym, ".", keySep)
	case "rust":
		parts := strings.Split(name, "::")
		if len(parts) < 2 {
			return ""
		}
		parts[0] = strings.ReplaceAll(parts[0], "-", "_")
		return strings.Join(parts, keySep)
	}
	return ""
}

// keySep joins the parts of a symbol key of safedep/code.
const keySep = "//"
