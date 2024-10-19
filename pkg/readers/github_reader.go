package readers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/google/go-github/v54/github"
	giturl "github.com/kubescape/go-git-url"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/parser"
)

type GitHubReaderConfig struct {
	Urls                         []string
	LockfileAs                   string
	SkipGitHubDependencyGraphAPI bool
}

type githubReader struct {
	client *github.Client
	config GitHubReaderConfig
}

// NewGithubReader creates a [PackageManifestReader] that can be used to read
// one or more `github_urls` interpreted as `lockfileAs`. When `lockfileAs` is empty
// the parser auto-detects the format based on file name. This reader fails and
// returns an error on first error encountered while parsing github_urls
func NewGithubReader(client *github.Client,
	config GitHubReaderConfig) (PackageManifestReader, error) {
	return &githubReader{
		client: client,
		config: config,
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
	ctx := context.Background()

	// We will not fail fast! This is because when we are scanning multiple
	// github urls, which we may while scanning an entire org, we want to make
	// as much progress as possible while logging errors
	for _, github_url := range p.config.Urls {
		logger.Debugf("Processing Github URL: %s", github_url)

		gitURL, err := giturl.NewGitURL(github_url)
		if err != nil {
			logger.Errorf("Failed to parse Github URL: %s due to %v", github_url, err)
			continue
		}

		err = p.processRemoteDependencyGraph(ctx, p.client, gitURL, handler)
		if err != nil {
			logger.Debugf("Failed to process dependency graph for %s: %v",
				gitURL.GetURL().String(), err)

			logger.Debugf("Attempting github repository enumeration to find lockfiles")
			err = p.processTopLevelLockfiles(ctx, p.client, gitURL, handler)
			if err != nil {
				logger.Errorf("Failed to enumerate packages for: %s due to %v",
					github_url, err)
				continue
			}
		}
	}

	return nil
}

// This is used as a backup in case dependency insights are not enabled for a repository
// However to keep things within the Github API rate limit and not to have the need for cloning
// the entire repo, we will walk the top level files only to identify lockfiles to scan
func (p *githubReader) processTopLevelLockfiles(ctx context.Context, client *github.Client,
	gitUrl giturl.IGitURL, handler func(*models.PackageManifest, PackageReader) error) error {

	logger.Infof("Discovering lockfiles by enumerating %s", gitUrl.GetURL().String())

	repository, _, err := client.Repositories.Get(ctx, gitUrl.GetOwnerName(), gitUrl.GetRepoName())
	if err != nil {
		return err
	}

	targetBranch := repository.GetDefaultBranch()
	logger.Debugf("Using branch: %s", targetBranch)

	tree, _, err := client.Git.GetTree(ctx, gitUrl.GetOwnerName(), gitUrl.GetRepoName(),
		targetBranch, false)
	if err != nil {
		return err
	}

	logger.Infof("Found default branch tree @ %s with %d entries",
		tree.GetSHA(), len(tree.Entries))

	for _, entry := range tree.Entries {
		logger.Debugf("Attempting to find parser for: %s", entry.GetPath())

		parser, err := parser.FindParser(entry.GetPath(), "")
		if err != nil {
			continue
		}

		logger.Debugf("Found a valid lockfile parser for: %s", entry.GetPath())

		lfile, err := p.fetchRemoteFileToLocalFile(ctx, client,
			gitUrl.GetOwnerName(), gitUrl.GetRepoName(),
			entry.GetPath(), targetBranch)

		if err != nil {
			logger.Errorf("failed to fetch remote file: %v", err)
			continue
		}

		err = func() error {
			defer os.Remove(lfile)

			pm, err := parser.Parse(lfile)
			if err != nil {
				return err
			}

			pm.UpdateSourceAsGitRepository(gitUrl.GetHttpCloneURL(), entry.GetPath())
			pm.SetDisplayPath(entry.GetPath())
			pm.SetPath(entry.GetURL())

			err = handler(pm, NewManifestModelReader(pm))
			if err != nil {
				return err
			}

			return nil
		}()

		if err != nil {
			logger.Errorf("Failed to handle lockfile %s due to %v",
				entry.GetPath(), err)
		}
	}

	return nil
}

func (p *githubReader) processRemoteDependencyGraph(ctx context.Context, client *github.Client,
	gitUrl giturl.IGitURL, handler func(*models.PackageManifest,
		PackageReader) error) error {
	if p.config.SkipGitHubDependencyGraphAPI {
		return errors.New("dependency graph API is disabled in the configuration")
	}

	logger.Infof("Fetching dependency graph from %s", gitUrl.GetURL().String())

	lf, err := p.fetchRemoteDependencyGraphToFile(ctx, client,
		gitUrl.GetOwnerName(), gitUrl.GetRepoName())
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

	if manifest.GetPackagesCount() == 0 {
		return errors.New("no packages identified from SBOM")
	}

	logger.Infof("Overriding manifest display path to: %s", gitUrl.GetHttpCloneURL())

	// Override the display path because local path of the downloaded
	// SBOM does not actually have a meaning. Also there isn't any path.
	manifest.UpdateSourceAsGitRepository(gitUrl.GetHttpCloneURL(), "")
	manifest.SetDisplayPath(gitUrl.GetHttpCloneURL())
	manifest.SetPath("")

	return handler(manifest, NewManifestModelReader(manifest))
}

func (p *githubReader) fetchRemoteDependencyGraphToFile(ctx context.Context, client *github.Client,
	org, repo string) (string, error) {
	sbom, _, err := client.DependencyGraph.GetSBOM(ctx, org, repo)
	if err != nil {
		return "", fmt.Errorf("failed to fetch SBOM from Github: %v, you may have to enable Dependency Graph for your repository", err)
	}

	sbom_bytes, err := json.Marshal(sbom.SBOM)
	if err != nil {
		return "", fmt.Errorf("error converting sbom to json: %v", err)
	}

	lfile, err := os.CreateTemp("", "vet-github-sbom")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file: %v", err)
	}

	_, err = lfile.Write(sbom_bytes)
	if err != nil {
		return "", fmt.Errorf("failed to write sbom into temp file: %v", err)
	}

	defer lfile.Close()
	return lfile.Name(), nil
}

func (p *githubReader) fetchRemoteFileToLocalFile(ctx context.Context, client *github.Client,
	org, repo, path, ref string) (string, error) {
	fileContent, _, _, err := client.Repositories.GetContents(ctx, org, repo, path,
		&github.RepositoryContentGetOptions{
			Ref: ref,
		})

	if err != nil {
		return "", fmt.Errorf("failed to fetch file from github: %v", err)
	}

	fileContentDecoded, err := fileContent.GetContent()
	if err != nil {
		return "", err
	}

	file, err := os.CreateTemp("", "vet-github-")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file: %v", err)
	}

	defer file.Close()

	_, err = file.Write([]byte(fileContentDecoded))
	if err != nil {
		return "", err
	}

	return file.Name(), nil
}
