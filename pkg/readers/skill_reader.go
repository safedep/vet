package readers

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-github/v70/github"
	"github.com/google/osv-scanner/pkg/lockfile"
	giturl "github.com/kubescape/go-git-url"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
)

// SkillReaderConfig configures the skill reader
type SkillReaderConfig struct {
	// Skill specification in format: owner/repo or https://github.com/owner/repo
	SkillSpec string
}

type skillReader struct {
	client *github.Client
	config SkillReaderConfig
}

var (
	_ PackageManifestReader = &skillReader{}
	_ PackageReader         = &skillReader{}
)

// NewSkillReader creates a PackageManifestReader for Agent Skills
// Skills are represented as GitHub repositories and treated as GitHub Actions packages
// for the purpose of malware analysis
func NewSkillReader(client *github.Client, config SkillReaderConfig) (*skillReader, error) {
	if config.SkillSpec == "" {
		return nil, fmt.Errorf("skill specification is required")
	}

	return &skillReader{
		client: client,
		config: config,
	}, nil
}

func (r *skillReader) Name() string {
	return "Agent Skill Reader"
}

func (r *skillReader) ApplicationName() (string, error) {
	gitURL, err := r.parseSkillSpec()
	if err != nil {
		return "", err
	}
	return gitURL.GetRepoName(), nil
}

// EnumManifests creates a package manifest representing the skill as a GitHub Actions package
func (r *skillReader) EnumManifests(handler func(*models.PackageManifest, PackageReader) error) error {
	gitURL, err := r.parseSkillSpec()
	if err != nil {
		return fmt.Errorf("failed to parse skill specification: %w", err)
	}

	ctx := context.Background()
	repository, _, err := r.client.Repositories.Get(ctx, gitURL.GetOwnerName(), gitURL.GetRepoName())
	if err != nil {
		return fmt.Errorf("failed to fetch GitHub repository: %w", err)
	}

	logger.Infof("Found skill repository: %s (stars: %d, forks: %d)",
		repository.GetFullName(),
		repository.GetStargazersCount(),
		repository.GetForksCount())

	// Create a manifest representing the skill as a GitHub Actions package
	manifest := r.createSkillManifest(gitURL, repository)

	return handler(manifest, r)
}

// EnumPackages implements PackageReader interface
func (r *skillReader) EnumPackages(handler func(*models.Package) error) error {
	// Skills don't enumerate individual packages
	// This is a no-op for skill reader
	return nil
}

// parseSkillSpec parses the skill specification and returns a git URL
// Supports formats:
// - owner/repo
// - https://github.com/owner/repo
// - https://github.com/owner/repo.git
func (r *skillReader) parseSkillSpec() (giturl.IGitURL, error) {
	spec := r.config.SkillSpec

	// If it doesn't contain a scheme, assume it's in owner/repo format
	if !strings.Contains(spec, "://") {
		// Validate basic format
		parts := strings.Split(spec, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("invalid skill specification format, expected 'owner/repo' or GitHub URL")
		}
		spec = fmt.Sprintf("https://github.com/%s", spec)
	}

	gitURL, err := giturl.NewGitURL(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to parse skill URL: %w", err)
	}

	// Ensure it's a GitHub URL
	if gitURL.GetHostName() != "github.com" {
		return nil, fmt.Errorf("skill must be hosted on GitHub, got: %s", gitURL.GetHostName())
	}

	return gitURL, nil
}

// createSkillManifest creates a package manifest representing the skill
// The skill is modeled as a GitHub Actions package for malware analysis
func (r *skillReader) createSkillManifest(gitURL giturl.IGitURL, repo *github.Repository) *models.PackageManifest {
	// Use the default branch as the version
	version := repo.GetDefaultBranch()
	if version == "" {
		version = "main"
	}

	manifest := models.NewPackageManifestFromGitHub(
		gitURL.GetHttpCloneURL(),
		"skill.json", // Virtual path representing the skill
		gitURL.GetHttpCloneURL(),
		models.EcosystemGitHubActions, // Treat as GitHub Actions for Malysis
	)

	// Set a display path that makes sense for skills
	manifest.SetDisplayPath(fmt.Sprintf("skill://%s/%s", gitURL.GetOwnerName(), gitURL.GetRepoName()))

	// Create a package representing the skill
	pkg := &models.Package{
		PackageDetails: lockfile.PackageDetails{
			Name:      fmt.Sprintf("%s/%s", gitURL.GetOwnerName(), gitURL.GetRepoName()),
			Version:   version,
			Ecosystem: lockfile.Ecosystem(models.EcosystemGitHubActions),
		},
		Depth:    0,
		Manifest: manifest,
	}

	// Add repository metadata if available
	if repo.GetDescription() != "" {
		logger.Debugf("Skill description: %s", repo.GetDescription())
	}

	manifest.AddPackage(pkg)
	manifest.DependencyGraph.AddNode(pkg)

	return manifest
}
