//go:build cgo

package codeusage

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sync"

	callgraphv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/code/callgraph/v1"
	"github.com/safedep/code/plugin/callgraph"
	"google.golang.org/protobuf/encoding/protojson"
	"gopkg.in/yaml.v3"
)

// signatureFiles are the code signatures, one YAML file for each product,
// under <vendor>/<category>/.
//
//go:embed signatures
var signatureFiles embed.FS

// signatureFile is the layout of a signature file.
type signatureFile struct {
	Version    string           `yaml:"version"`
	Signatures []map[string]any `yaml:"signatures"`
}

// loadSignatures reads and checks the embedded signatures once.
var loadSignatures = sync.OnceValues(func() ([]*callgraphv1.Signature, error) {
	return readSignatures(signatureFiles)
})

// readSignatures reads every signature file of fsys. The YAML keys are the
// JSON names of the protobuf message, so protojson decodes each signature.
func readSignatures(fsys fs.FS) ([]*callgraphv1.Signature, error) {
	var out []*callgraphv1.Signature
	seen := map[string]string{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || (path.Ext(p) != ".yaml" && path.Ext(p) != ".yml") {
			return err
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		var file signatureFile
		if err := yaml.Unmarshal(data, &file); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		for _, raw := range file.Signatures {
			b, err := json.Marshal(raw)
			if err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			var sig callgraphv1.Signature
			if err := protojson.Unmarshal(b, &sig); err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			if other, dup := seen[sig.GetId()]; dup {
				return fmt.Errorf("%s: signature %s is also in %s", p, sig.GetId(), other)
			}
			seen[sig.GetId()] = p
			out = append(out, &sig)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := callgraph.ValidateSignatures(out); err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}
	return out, nil
}

func signatureOf(s *callgraphv1.Signature) Signature {
	return Signature{
		ID: s.GetId(), Description: s.GetDescription(), Vendor: s.GetVendor(), Product: s.GetProduct(),
		Service: s.GetService(), Tags: s.GetTags(),
	}
}
