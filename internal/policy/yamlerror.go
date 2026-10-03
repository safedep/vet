package policy

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	yamlLine     = regexp.MustCompile(`^yaml: line (\d+): (.*)$`)
	unknownField = regexp.MustCompile(`^line (\d+): field (\S+) not found in type policy\.(\w+)$`)
	wrongType    = regexp.MustCompile("^line (\\d+): cannot unmarshal !!\\w+(?: `(.*)`)? into (\\S+)$")
	typeLine     = regexp.MustCompile(`^line (\d+): (.*)$`)
)

// yamlTypes names the types of the file format in an error, with the
// fields that each one has.
var yamlTypes = map[string]struct {
	noun string
	typ  reflect.Type
}{
	"document":    {"policy file", reflect.TypeFor[document]()},
	"Rule":        {"rule", reflect.TypeFor[Rule]()},
	"Suppression": {"suppression", reflect.TypeFor[Suppression]()},
}

// yamlError turns an error of the YAML decoder into lines that name the
// file and the line, and no Go type:
//
//	bad.yml line 4: "fail" is not a field of a rule. A rule has id, description, when and action.
func yamlError(name string, err error) error {
	var te *yaml.TypeError
	if !errors.As(err, &te) {
		if m := yamlLine.FindStringSubmatch(err.Error()); m != nil {
			return fmt.Errorf("%s line %s: %s", name, m[1], m[2])
		}
		return fmt.Errorf("%s: %s", name, strings.TrimPrefix(err.Error(), "yaml: "))
	}
	lines := make([]string, 0, len(te.Errors))
	for _, e := range te.Errors {
		lines = append(lines, typeErrorLine(name, e))
	}
	return errors.New(strings.Join(lines, "\n"))
}

func typeErrorLine(name, e string) string {
	if m := unknownField.FindStringSubmatch(e); m != nil {
		if t, ok := yamlTypes[m[3]]; ok {
			return fmt.Sprintf("%s line %s: %q is not a field of a %s. A %s has %s.",
				name, m[1], m[2], t.noun, t.noun, list(yamlFields(t.typ)))
		}
	}
	if m := wrongType.FindStringSubmatch(e); m != nil {
		value := "the value"
		if m[2] != "" {
			value = fmt.Sprintf("the value %q", m[2])
		}
		return fmt.Sprintf("%s line %s: %s must be %s", name, m[1], value, goType(m[3]))
	}
	if m := typeLine.FindStringSubmatch(e); m != nil {
		return fmt.Sprintf("%s line %s: %s", name, m[1], m[2])
	}
	return fmt.Sprintf("%s: %s", name, e)
}

// goType names a Go type of the file format for a person.
func goType(t string) string {
	switch {
	case strings.HasPrefix(t, "int"):
		return "a whole number"
	case t == "bool":
		return "true or false"
	case t == "string" || t == "policy.Action":
		return "a string"
	case strings.HasPrefix(t, "[]"):
		return "a list"
	default:
		return "a map of fields"
	}
}

// yamlFields returns the YAML names of the fields of a struct type.
func yamlFields(t reflect.Type) []string {
	var out []string
	for f := range t.Fields() {
		tag, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if f.IsExported() && tag != "" && tag != "-" {
			out = append(out, tag)
		}
	}
	return out
}

// list joins words as "a, b and c".
func list(words []string) string {
	if len(words) < 2 {
		return strings.Join(words, "")
	}
	return strings.Join(words[:len(words)-1], ", ") + " and " + words[len(words)-1]
}
