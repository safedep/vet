package analyzer

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/safedep/dry/adapters"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/common/utils"
	"github.com/safedep/vet/pkg/models"
	"gopkg.in/yaml.v3"
)

const ghaPinAnalyzerName = "GHAPinAnalyzer"

var (
	// Matches owner/repo@ref or owner/repo/path@ref
	ghaUsesRegex   = regexp.MustCompile(`^([^@]+)@(.+)$`)
	// Matches both SHA-1 (40 hex chars) and SHA-256 (64 hex chars) commit hashes
	commitSHARegex = regexp.MustCompile(`^[a-f0-9]{40}$|^[a-f0-9]{64}$`)
)

// ghaSHAResolver resolves a GitHub ref (tag/branch) to a commit SHA.
type ghaSHAResolver interface {
	ResolveSHA(ctx context.Context, owner, repo, ref string) (string, error)
}

// githubClientSHAResolver uses the GitHub API to resolve refs.
type githubClientSHAResolver struct {
	client *adapters.GithubClient
}

func (r *githubClientSHAResolver) ResolveSHA(ctx context.Context, owner, repo, ref string) (string, error) {
	return utils.ResolveGitHubRepositoryCommitSHA(ctx, r.client, owner, repo, ref)
}

type GHAPinAnalyzerConfig struct{}

type ghaPinAnalyzer struct {
	config   GHAPinAnalyzerConfig
	resolver ghaSHAResolver
	pinCount int
}

func NewGHAPinAnalyzer(githubClient *adapters.GithubClient, config GHAPinAnalyzerConfig) (Analyzer, error) {
	if githubClient == nil {
		return nil, fmt.Errorf("github client is required for GHA pin analyzer")
	}

	return &ghaPinAnalyzer{
		config:   config,
		resolver: &githubClientSHAResolver{client: githubClient},
	}, nil
}

func (a *ghaPinAnalyzer) Name() string {
	return ghaPinAnalyzerName
}

func (a *ghaPinAnalyzer) Analyze(manifest *models.PackageManifest, handler AnalyzerEventHandler) error {
	if manifest.Ecosystem != models.EcosystemGitHubActions {
		return nil
	}

	filePath := manifest.Path
	logger.Infof("[GHA Pin] Processing workflow file: %s", filePath)

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read workflow file %s: %w", filePath, err)
	}

	doc := &yaml.Node{}
	if err := yaml.Unmarshal(data, doc); err != nil {
		return fmt.Errorf("failed to parse workflow YAML %s: %w", filePath, err)
	}

	modified, err := a.pinActionsInDocument(doc, filePath, handler)
	if err != nil {
		return err
	}

	if !modified {
		logger.Debugf("[GHA Pin] No unpinned actions found in %s", filePath)
		return nil
	}

	if err := a.writeYAMLDocument(filePath, data, doc); err != nil {
		return fmt.Errorf("failed to write pinned workflow %s: %w", filePath, err)
	}

	logger.Infof("[GHA Pin] Pinned actions in %s", filePath)
	return nil
}

func (a *ghaPinAnalyzer) Finish() error {
	if a.pinCount > 0 {
		logger.Infof("[GHA Pin] Pinned %d GitHub Action(s) to commit SHAs", a.pinCount)
	}

	return nil
}

// pinActionsInDocument walks the YAML AST and pins all unpinned action references.
func (a *ghaPinAnalyzer) pinActionsInDocument(doc *yaml.Node, filePath string, handler AnalyzerEventHandler) (bool, error) {
	usesNodes := a.findUsesNodes(doc)
	if len(usesNodes) == 0 {
		return false, nil
	}

	modified := false
	for _, node := range usesNodes {
		changed, err := a.pinUsesNode(node, filePath, handler)
		if err != nil {
			logger.Warnf("[GHA Pin] Failed to pin action %q in %s: %v", node.Value, filePath, err)
			continue
		}
		if changed {
			modified = true
		}
	}

	return modified, nil
}

// pinUsesNode resolves a single uses: value node and patches it in-place.
func (a *ghaPinAnalyzer) pinUsesNode(node *yaml.Node, filePath string, handler AnalyzerEventHandler) (bool, error) {
	matches := ghaUsesRegex.FindStringSubmatch(node.Value)
	if len(matches) < 3 {
		return false, nil
	}

	actionPath := matches[1] // e.g., "actions/checkout" or "actions/checkout/subpath"
	ref := matches[2]        // e.g., "v3" or "6edd4406..."

	// Already pinned to a commit SHA
	if commitSHARegex.MatchString(strings.ToLower(ref)) {
		return false, nil
	}

	// Extract owner/repo from the action path (may contain subpath like owner/repo/path)
	parts := strings.SplitN(actionPath, "/", 3)
	if len(parts) < 2 {
		return false, fmt.Errorf("invalid action reference: %s", node.Value)
	}
	owner, repo := parts[0], parts[1]

	sha, err := a.resolver.ResolveSHA(context.Background(), owner, repo, ref)
	if err != nil {
		return false, fmt.Errorf("failed to resolve %s/%s@%s: %w", owner, repo, ref, err)
	}

	// Patch the node value
	newValue := fmt.Sprintf("%s@%s", actionPath, sha)
	oldValue := node.Value
	node.Value = newValue
	node.LineComment = ref

	a.pinCount++

	logger.Infof("[GHA Pin] Pinned %s -> %s@%s # %s", oldValue, actionPath, sha, ref)

	// Emit event for reporters
	if err := handler(&AnalyzerEvent{
		Source:  ghaPinAnalyzerName,
		Type:    ET_GitHubActionPinned,
		Message: fmt.Sprintf("Pinned %s to %s # %s", oldValue, newValue, ref),
	}); err != nil {
		return true, err
	}

	return true, nil
}

// findUsesNodes walks the YAML AST and returns all scalar value nodes for "uses" keys.
func (a *ghaPinAnalyzer) findUsesNodes(node *yaml.Node) []*yaml.Node {
	if node == nil {
		return nil
	}

	var results []*yaml.Node

	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			results = append(results, a.findUsesNodes(child)...)
		}
	case yaml.MappingNode:
		for i := 0; i < len(node.Content)-1; i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]

			if keyNode.Kind == yaml.ScalarNode && keyNode.Value == "uses" &&
				valueNode.Kind == yaml.ScalarNode {
				results = append(results, valueNode)
			} else {
				results = append(results, a.findUsesNodes(valueNode)...)
			}
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			results = append(results, a.findUsesNodes(child)...)
		}
	}

	return results
}

// writeYAMLDocument serializes the modified AST back to the file,
// preserving the original file's trailing newline behavior.
func (a *ghaPinAnalyzer) writeYAMLDocument(filePath string, originalData []byte, doc *yaml.Node) error {
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)

	if err := encoder.Encode(doc); err != nil {
		return fmt.Errorf("failed to encode YAML: %w", err)
	}

	if err := encoder.Close(); err != nil {
		return fmt.Errorf("failed to close YAML encoder: %w", err)
	}

	output := buf.Bytes()

	// Preserve trailing newline behavior of original file
	originalEndsWithNewline := len(originalData) > 0 && originalData[len(originalData)-1] == '\n'
	outputEndsWithNewline := len(output) > 0 && output[len(output)-1] == '\n'

	if originalEndsWithNewline && !outputEndsWithNewline {
		output = append(output, '\n')
	} else if !originalEndsWithNewline && outputEndsWithNewline {
		output = bytes.TrimRight(output, "\n")
	}

	return os.WriteFile(filePath, output, 0644)
}
