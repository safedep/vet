package readers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	giturl "github.com/kubescape/go-git-url"
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/internal/connect"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/common/utils/file_utils"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/parser"
)

type githubReader struct {
	lockfiles  []string
	lockfileAs string
}

// NewGithubReader creates a [PackageManifestReader] that can be used to read
// one or more `lockfiles` interpreted as `lockfileAs`. When `lockfileAs` is empty
// the parser auto-detects the format based on file name. This reader fails and
// returns an error on first error encountered while parsing lockfiles
func NewGithubReader(github_urls []string, lockfileAs string) (PackageManifestReader, error) {
	return &githubReader{
		lockfiles:  github_urls,
		lockfileAs: lockfileAs,
	}, nil
}

// Name returns the name of this reader
func (p *githubReader) Name() string {
	return "Github Based Package Manifest Reader"
}

// EnumManifests iterates over the provided lockfile as and attempts to parse
// it as `lockfileAs` parser. To auto-detect parser, set `lockfileAs` to empty
// string during initialization.
func (p *githubReader) EnumManifests(handler func(*models.PackageManifest,
	PackageReader) error) error {
	var err error
	context := context.Background()
	client, err := connect.GetGithubClient()
	if err != nil {
		return err
	}

	orgs, _, err := client.Organizations.List(context, "", nil)
	if err != nil {
		return err
	}
	logger.Debugf("Organizations found %v", orgs)

	for _, git_url := range p.lockfiles {
		gitURL, err := giturl.NewGitURL(git_url) // initialize and parse the URL
		if err != nil {
			return err
		}
		lockfileAs := p.lockfileAs
		if utils.IsEmptyString(lockfileAs) {
			lockfileAs = "bom-spdx"
		}

		sbom, _, err := client.DependencyGraph.GetSBOM(context,
			gitURL.GetOwnerName(), gitURL.GetRepoName())
		if err != nil {
			return fmt.Errorf("getSBOM from Remote server returned error: %v", err)
		}

		sbom_bytes, err := json.Marshal(sbom.SBOM)
		if err != nil {
			return fmt.Errorf("error converting sbom to json: %v", err)
		}
		io_reader := io.NopCloser(bytes.NewReader(sbom_bytes))
		lfile, err := file_utils.CopyToTempFile(io_reader, os.TempDir(), "sbom")
		if err != nil {
			return fmt.Errorf("error copying sbom json bytes to the file %v", err)
		}
		defer lfile.Close()

		lf := lfile.Name()
		// defer os.Remove(lfile.Name())
		lfParser, err := parser.FindParser(lf, lockfileAs)
		if err != nil {
			return err
		}

		manifest, err := lfParser.Parse(lf)
		if err != nil {
			return err
		}

		err = handler(&manifest, NewManifestModelReader(&manifest))
		if err != nil {
			return err
		}
	}

	return nil
}
