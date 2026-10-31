package codeusage

import "strings"

// SymbolKey turns the name of a fix site, as a symbol record writes it, into
// the symbol key of safedep/code. A Go name is the import path, a dot and the
// symbol, as golang.org/x/net/html.Tokenizer.Next. The last element of an
// import path can hold a dot, as gopkg.in/yaml.v3, so a name in the root
// package of its module splits after the module path. A Rust name is a path
// with ::, as time::OffsetDateTime::now_local, and its crate name folds - to
// _. A Python name is the dotted path of the function or the method, as
// yaml.load or requests.sessions.Session.get, and a record can write a
// colon between the module and the name, as yaml:load. It returns "" for a
// language that has no rule.
func SymbolKey(language, module, name string) string {
	switch language {
	case "python":
		name = strings.ReplaceAll(name, ":", ".")
		if !strings.Contains(name, ".") {
			return ""
		}
		return strings.ReplaceAll(name, ".", keySep)
	case "go":
		pkg, sym := name, ""
		if module != "" && strings.HasPrefix(name, module+".") {
			pkg, sym = module, name[len(module)+1:]
		} else if slash := strings.LastIndex(name, "/"); slash >= 0 {
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
