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
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/internal/connect"
	"github.com/safedep/vet/pkg/common/utils/file_utils"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/parser"
)

type githubReader struct {
	github_urls []string
	lockfileAs  string
}

// NewGithubReader creates a [PackageManifestReader] that can be used to read
// one or more `github_urls` interpreted as `lockfileAs`. When `lockfileAs` is empty
// the parser auto-detects the format based on file name. This reader fails and
// returns an error on first error encountered while parsing github_urls
func NewGithubReader(github_urls []string, lockfileAs string) (PackageManifestReader, error) {
	return &githubReader{
		github_urls: github_urls,
		lockfileAs:  lockfileAs,
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
	client, err := connect.GetGithubClient()
	if err != nil {
		return err
	}

	for _, github_url := range p.github_urls {
		//Process github_url and return the parsed content of the package file
		gitURL, err := giturl.NewGitURL(github_url) // initialize and parse the URL
		if err != nil {
			return err
		}

		err = processRemoteLockfile(ctx, client, gitURL, p.lockfileAs, handler)
		if err != nil {
			return err
		}
	}

	return nil
}

/*
Infer lockfileas based on input lockfileas (may be empty), or filepath
*/
func inferLockfileAs(ilockfileas, filepath string) string {
	// Check and set the lockfile-as
	lockfileAs := ilockfileas
	if utils.IsEmptyString(lockfileAs) {
		lockfileAs = "bom-spdx"
	}
	return lockfileAs
}

/*
fetch remote file / repo and invoke handler
*/
func processRemoteLockfile(ctx context.Context, client *github.Client,
	gitUrl giturl.IGitURL, inlockfileAs string, handler func(*models.PackageManifest,
		PackageReader) error) error {

	org := gitUrl.GetOwnerName()
	repo := gitUrl.GetRepoName()
	path := gitUrl.GetPath()
	// Check and set the lockfile-as
	lockfileAs := inferLockfileAs(inlockfileAs, path)

	//Get the Remote Package File
	lf, err := fetchRemoteFile(ctx, client, org, repo, lockfileAs)
	if err != nil {
		return err
	}
	defer os.Remove(lf)

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

	return nil
}

/**
 * fetchRemoteFile processes the GitHub URL, downloads the content, and returns the filepath with the content.
 *
 * @param ctx       The context for the operation.
 * @param client    The GitHub client used for interacting with the API.
 * @param github_url   The GitHub URL to process.
 * @param lockfileAs The lockfile type to use.
 *
 * @return string    The filepath to the temporary file containing the downloaded content.
 * @return error     Any error encountered during the operation.
 *
 * Note: The caller should remove the filepath returned when done.
 **/
func fetchRemoteFile(ctx context.Context, client *github.Client,
	org, repo, lockfileAs string) (string, error) {
	sbom, _, err := client.DependencyGraph.GetSBOM(ctx, org, repo)
	if err != nil {
		return "", fmt.Errorf("getSBOM from Remote server returned error: %v", err)
	}

	sbom_bytes, err := json.Marshal(sbom.SBOM)
	if err != nil {
		return "", fmt.Errorf("error converting sbom to json: %v", err)
	}
	//Marshal the sbom to json and write to a tempory file
	io_reader := io.NopCloser(bytes.NewReader(sbom_bytes))
	lfile, err := file_utils.CopyToTempFile(io_reader, os.TempDir(), "sbom")
	if err != nil {
		return "", fmt.Errorf("error copying sbom json bytes to the file %v", err)
	}
	defer lfile.Close()

	return lfile.Name(), nil
}
