package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
)

var dotFileNameCleanerRegexp = regexp.MustCompile(`[^\w\d\.\-]`)

type DotGraphReporter struct {
	Directory string
}

func NewDotGraphReporter(directory string) (Reporter, error) {
	if _, err := os.Stat(directory); err != nil {
		err := os.MkdirAll(directory, 0755)
		if err != nil {
			return nil, err
		}
	}

	return &DotGraphReporter{Directory: directory}, nil
}

func (r *DotGraphReporter) Name() string {
	return "Graphviz Dot Graph"
}

func (r *DotGraphReporter) AddManifest(manifest *models.PackageManifest) {
	dotFileName := r.dotFileNameFromManifestPath(manifest.GetPath())
	dotFilePath := filepath.Join(r.Directory, dotFileName+".dot")

	writer, err := os.Create(dotFilePath)
	if err != nil {
		logger.Errorf("dotGraphReporter: failed to create file %s: %v", dotFilePath, err)
		return
	}

	defer writer.Close()

	renderedGraph, err := r.dotRenderDependencyGraph(manifest.DependencyGraph)
	if err != nil {
		logger.Errorf("dotGraphReporter: failed to render graph: %v", err)
		return
	}

	_, err = writer.WriteString(renderedGraph)
	if err != nil {
		logger.Errorf("dotGraphReporter: failed to write to file %s: %v", dotFilePath, err)
		return
	}
}

func (r *DotGraphReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {}

func (r *DotGraphReporter) AddPolicyEvent(event *policy.PolicyEvent) {}

func (r *DotGraphReporter) Finish() error {
	return nil
}

func (r *DotGraphReporter) dotFileNameFromManifestPath(path string) string {
	s := filepath.Clean(path)
	s = dotFileNameCleanerRegexp.ReplaceAllString(s, "_")

	return s
}

func (r *DotGraphReporter) dotRenderDependencyGraph(dg *models.DependencyGraph[*models.Package]) (string, error) {
	var sb strings.Builder
	sb.WriteString("digraph {\n")
	sb.WriteString("  rankdir=LR;\n")
	sb.WriteString("  node [shape=box];\n")

	// Generate the node names
	for _, node := range dg.GetNodes() {
		sb.WriteString("  ")
		sb.WriteString("\"" + r.nodeNameForPackage(node.Data) + "\"")
		sb.WriteString(";\n")
	}

	// Add the relations
	for _, node := range dg.GetNodes() {
		for _, edge := range node.Children {
			sb.WriteString("  ")
			sb.WriteString("\"" + r.nodeNameForPackage(node.Data) + "\"")
			sb.WriteString(" -> ")
			sb.WriteString("\"" + r.nodeNameForPackage(edge) + "\"")
			sb.WriteString(";\n")
		}
	}

	sb.WriteString("}\n")
	return sb.String(), nil
}

func (r *DotGraphReporter) nodeNameForPackage(pkg *models.Package) string {
	return fmt.Sprintf("%s@%s", pkg.GetName(), pkg.GetVersion())
}
