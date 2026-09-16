package aitool

import (
	"context"
	"os"
	"path/filepath"
)

const (
	geminiApp        = "gemini_cli"
	geminiAppDisplay = "Gemini CLI"
)

type geminiDiscoverer struct {
	homeDir    string
	projectDir string
	config     DiscoveryConfig
}

// NewGeminiDiscoverer creates a Gemini CLI config discoverer.
// It reads ~/.gemini/settings.json which uses the standard mcpServers format.
func NewGeminiDiscoverer(config DiscoveryConfig) (AIToolReader, error) {
	homeDir := config.HomeDir
	if homeDir == "" {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return nil, err
		}
	}
	return &geminiDiscoverer{
		homeDir:    homeDir,
		projectDir: config.ProjectDir,
		config:     config,
	}, nil
}

func (d *geminiDiscoverer) Name() string { return "Gemini CLI Config" }
func (d *geminiDiscoverer) App() string  { return geminiApp }

func (d *geminiDiscoverer) EnumTools(_ context.Context, handler AIToolHandlerFn) error {
	if d.config.ScopeEnabled(AIToolScopeSystem) {
		geminiDir := filepath.Join(d.homeDir, ".gemini")
		settingsPath := filepath.Join(geminiDir, "settings.json")

		// System-level: ~/.gemini/settings.json (standard mcpServers format)
		if cfg, err := parseMCPAppConfig(settingsPath); err == nil {
			if err := emitMCPServers(cfg, settingsPath, AIToolScopeSystem, geminiApp, geminiAppDisplay, handler); err != nil {
				return err
			}
		}

		// Emit coding_agent if the ~/.gemini/ directory exists
		if info, err := os.Stat(geminiDir); err == nil && info.IsDir() {
			agent := &AITool{
				Name:       geminiAppDisplay,
				Type:       AIToolTypeCodingAgent,
				Scope:      AIToolScopeSystem,
				App:        geminiApp,
				AppDisplay: geminiAppDisplay,
				ConfigPath: geminiDir,
				Agent:      &AgentConfig{},
			}
			agent.ID = generateID(agent.App, string(agent.Type), string(agent.Scope), agent.Name, agent.ConfigPath)
			agent.SourceID = generateSourceID(agent.App, agent.ConfigPath)

			if err := handler(agent); err != nil {
				return err
			}
		}
	}

	if d.config.ScopeEnabled(AIToolScopeProject) && d.projectDir != "" {
		// Project-level: GEMINI.md instruction file
		var instructionFiles []string

		geminiMDPath := filepath.Join(d.projectDir, "GEMINI.md")
		if _, err := os.Stat(geminiMDPath); err == nil {
			instructionFiles = append(instructionFiles, geminiMDPath)
		}

		if len(instructionFiles) > 0 {
			tool := &AITool{
				Name:       geminiAppDisplay,
				Type:       AIToolTypeProjectConfig,
				Scope:      AIToolScopeProject,
				App:        geminiApp,
				AppDisplay: geminiAppDisplay,
				ConfigPath: d.projectDir,
				Agent: &AgentConfig{
					InstructionFiles: instructionFiles,
				},
			}
			tool.ID = generateID(tool.App, string(tool.Type), string(tool.Scope), tool.Name, tool.ConfigPath)
			tool.SourceID = generateSourceID(tool.App, tool.ConfigPath)

			if err := handler(tool); err != nil {
				return err
			}
		}
	}

	return nil
}
