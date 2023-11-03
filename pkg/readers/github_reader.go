package readers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/google/go-github/v54/github"
	giturl "github.com/kubescape/go-git-url"
	"github.com/safedep/vet/pkg/common/utils"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/parser"
)

type githubReader struct {
	client      *github.Client
	github_urls []string
	lockfileAs  string
}

// NewGithubReader creates a [PackageManifestReader] that can be used to read
// one or more `github_urls` interpreted as `lockfileAs`. When `lockfileAs` is empty
// the parser auto-detects the format based on file name. This reader fails and
// returns an error on first error encountered while parsing github_urls
func NewGithubReader(client *github.Client,
	github_urls []string,
	lockfileAs string) (PackageManifestReader, error) {

	return &githubReader{
		client:      client,
		github_urls: github_urls,
		lockfileAs:  lockfileAs, // This is unused currently
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
	ctx := context.Background()
	if err != nil {
		return err
	}

	for _, github_url := range p.github_urls {
		gitURL, err := giturl.NewGitURL(github_url)
		if err != nil {
			return err
		}

		err = p.processRemoteDependencyGraph(ctx, p.client, gitURL, handler)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *githubReader) processRemoteDependencyGraph(ctx context.Context, client *github.Client,
	gitUrl giturl.IGitURL, handler func(*models.PackageManifest,
		PackageReader) error) error {

	org := gitUrl.GetOwnerName()
	repo := gitUrl.GetRepoName()

	lf, err := p.fetchRemoteDependencyGraphToFile(ctx, client, org, repo)
	if err != nil {
		return err
	}

	defer os.Remove(lf)

	lfParser, err := parser.FindParser(lf, parser.LockfileAsBomSpdx)
	if err != nil {
		return err
	}

	manifest, err := lfParser.Parse(lf)
	if err != nil {
		return err
	}

	err = handler(manifest, NewManifestModelReader(manifest))
	if err != nil {
		return err
	}

	return nil
}

/**
 * fetchRemoteFile processes the GitHub URL, downloads the content, and returns the filepath with the content.
 *
 * @param ctx       The context for the operation.
 * @param client    The GitHub client used for interacting with the API.
 * @param github_url   The GitHub URL to process.
 *
 * @return string    The filepath to the temporary file containing the downloaded content.
 * @return error     Any error encountered during the operation.
 *
 * Note: The caller should remove the filepath returned when done.
 **/
func (p *githubReader) fetchRemoteDependencyGraphToFile(ctx context.Context, client *github.Client,
	org, repo string) (string, error) {
	sbom, _, err := client.DependencyGraph.GetSBOM(ctx, org, repo)
	if err != nil {
		return "", fmt.Errorf("failed to fetch SBOM from Github: %v", err)
	}

	sbom_bytes, err := json.Marshal(sbom.SBOM)
	if err != nil {
		return "", fmt.Errorf("error converting sbom to json: %v", err)
	}

	io_reader := io.NopCloser(bytes.NewReader(sbom_bytes))
	lfile, err := utils.CopyToTempFile(io_reader, os.TempDir(), "gh-sbom")
	if err != nil {
		return "", fmt.Errorf("error copying sbom json bytes to the file %v", err)
	}

	defer lfile.Close()
	return lfile.Name(), nil
}
