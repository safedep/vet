package readers

import (
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/parser"
)

type lockfileReader struct {
	lockfiles  []string
	lockfileAs string
}

// NewLockfileReader creates a [PackageManifestReader] that can be used to read
// one or more `lockfiles` interpreted as `lockfileAs`. When `lockfileAs` is empty
// the parser auto-detects the format based on file name. This reader fails and
// returns an error on first error encountered while parsing lockfiles
func NewLockfileReader(lockfiles []string, lockfileAs string) (PackageManifestReader, error) {
	return &lockfileReader{
		lockfiles:  lockfiles,
		lockfileAs: lockfileAs,
	}, nil
}

// Name returns the name of this reader
func (p *lockfileReader) Name() string {
	return "Lockfiles Based Package Manifest Reader"
}

// EnumManifests iterates over the provided lockfile as and attempts to parse
// it as `lockfileAs` parser. To auto-detect parser, set `lockfileAs` to empty
// string during initialization.
func (p *lockfileReader) EnumManifests(handler func(*models.PackageManifest,
	PackageReader) error) error {
	for _, lf := range p.lockfiles {
		rf, rt, err := parser.ResolveParseTarget(lf, p.lockfileAs,
			[]parser.TargetScopeType{parser.TargetScopeAll})
		if err != nil {
			return err
		}

		lfParser, err := parser.FindParser(rf, rt)
		if err != nil {
			return err
		}

		manifest, err := lfParser.Parse(rf)
		if err != nil {
			return err
		}

		err = handler(manifest, NewManifestModelReader(manifest))
		if err != nil {
			return err
		}
	}

	return nil
}
