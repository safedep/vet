package main

import (
	"context"
	"fmt"

	"github.com/safedep/vet/agent"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/readers"
)

// In-memory data cache for query agent
type queryDataCache struct {
	manifests map[string]*models.PackageManifest
}

var _ readers.PackageManifestReader = (*queryDataCache)(nil)

func (c *queryDataCache) Name() string {
	return "Query Data Cache"
}

func (c *queryDataCache) ApplicationName() (string, error) {
	return "Query Agent Data Cache", nil
}

func (c *queryDataCache) EnumManifests(handler func(*models.PackageManifest, readers.PackageReader) error) error {
	for _, manifest := range c.manifests {
		if err := handler(manifest, nil); err != nil {
			return err
		}
	}

	return nil
}

func executeQueryAgent() error {
	ui.PrintMsg("Loading JSON dump files...")

	reader, err := readers.NewJsonDumpReader(queryLoadDirectory)
	if err != nil {
		return err
	}

	cache := &queryDataCache{
		manifests: make(map[string]*models.PackageManifest),
	}

	index := 0
	err = reader.EnumManifests(func(manifest *models.PackageManifest, reader readers.PackageReader) error {
		manifestID := fmt.Sprintf("%d-%s-%s-%s", index, manifest.GetControlTowerSpecEcosystem().String(),
			manifest.GetSource().GetNamespace(), manifest.GetSource().GetPath())

		cache.manifests[manifestID] = manifest
		index++

		return nil
	})
	if err != nil {
		return err
	}

	ui.PrintMsg("Loading JSON dump files... done")

	ui.PrintMsg("Connecting to MCP server...")

	toolBuilder, err := agent.NewMcpClientToolBuilder(agent.McpClientToolBuilderConfig{
		SseURL:        queryAgentMcpServerUrl,
		ClientName:    "vet-query-agent",
		ClientVersion: version,
	})
	if err != nil {
		return fmt.Errorf("failed to create MCP client tool builder: %w", err)
	}

	tools, err := toolBuilder.Build(context.Background())
	if err != nil {
		return fmt.Errorf("failed to connect to MCP server: %w", err)
	}

	ui.PrintMsg("Connected to MCP server")

	// TODO: Add the tool for query data cache access for the agent

	ui.PrintMsg("Creating model...")

	model, err := agent.BuildModelFromEnvironment()
	if err != nil {
		return fmt.Errorf("failed to create model: %w", err)
	}

	ui.PrintMsg("Creating agent...")

	agentExecutor, err := agent.NewReactQueryAgent(model, agent.ReactQueryAgentConfig{
		MaxSteps: 30,
	}, agent.WithTools(tools))
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}

	ui.PrintMsg("Starting agent interaction UI...")

	err = agent.RunAgentUI(agentExecutor, agent.NewMockSession())
	if err != nil {
		return fmt.Errorf("failed to start agent interaction UI: %w", err)
	}

	return fmt.Errorf("agent interaction UI exited with error: %w", err)
}
