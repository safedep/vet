package ai

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/safedep/vet/pkg/aitool"
	"github.com/safedep/vet/pkg/common/logger"
)

var (
	discoverScope      string
	discoverProjectDir string
	discoverReportJSON string
	discoverSilent     bool
)

func newDiscoverCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover AI tools, MCP servers, and coding agents",
		RunE: func(cmd *cobra.Command, args []string) error {
			redirectLogOutput(cmd)
			return runDiscover()
		},
	}

	cmd.Flags().StringVar(&discoverScope, "scope", "", "Limit scope: system, project, or empty for both")
	cmd.Flags().StringVarP(&discoverProjectDir, "project-dir", "D", "", "Project root for project-level discovery (default: cwd)")
	cmd.Flags().StringVar(&discoverReportJSON, "report-json", "", "Write JSON inventory to file")
	cmd.Flags().BoolVarP(&discoverSilent, "silent", "s", false, "Suppress default summary output")

	return cmd
}

func runDiscover() error {
	projectDir := discoverProjectDir
	if projectDir == "" {
		var err error
		projectDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}
	}

	config := aitool.DiscoveryConfig{
		ProjectDir: projectDir,
	}

	registry := aitool.DefaultRegistry()
	inventory := aitool.NewAIToolInventory()

	err := registry.Discover(config, func(tool *aitool.AITool) error {
		if discoverScope != "" && string(tool.Scope) != discoverScope {
			return nil
		}

		inventory.Add(tool)
		return nil
	})
	if err != nil {
		return err
	}

	if !discoverSilent {
		printSummaryTable(inventory)
	}

	if discoverReportJSON != "" {
		if err := writeJSONInventory(inventory, discoverReportJSON); err != nil {
			return fmt.Errorf("failed to write JSON report: %w", err)
		}
	}

	return nil
}

func printSummaryTable(inventory *aitool.AIToolInventory) {
	hosts := inventory.GroupByHost()

	fmt.Fprintf(os.Stderr, "\nDiscovered %d AI tool usage(s) across %d host(s)\n\n",
		len(inventory.Tools), len(hosts))

	if len(inventory.Tools) == 0 {
		return
	}

	tbl := table.NewWriter()
	tbl.SetOutputMirror(os.Stderr)
	tbl.SetStyle(table.StyleLight)

	tbl.AppendHeader(table.Row{"TYPE", "NAME", "HOST", "SCOPE", "DETAIL"})

	for _, tool := range inventory.Tools {
		detail := toolDetail(tool)
		tbl.AppendRow(table.Row{
			string(tool.Type),
			tool.Name,
			tool.Host,
			string(tool.Scope),
			detail,
		})
	}

	tbl.Render()
	fmt.Fprintln(os.Stderr)
}

func toolDetail(tool *aitool.AITool) string {
	switch tool.Type {
	case aitool.AIToolTypeMCPServer:
		if tool.MCPServer != nil {
			if tool.MCPServer.Command != "" {
				detail := string(tool.MCPServer.Transport) + ": " + tool.MCPServer.Command
				if len(tool.MCPServer.Args) > 0 {
					for _, arg := range tool.MCPServer.Args {
						detail += " " + arg
					}
				}
				return detail
			}
			if tool.MCPServer.URL != "" {
				return string(tool.MCPServer.Transport) + ": " + tool.MCPServer.URL
			}
		}
		return tool.ConfigPath
	case aitool.AIToolTypeCLITool:
		version := tool.GetMetaString("binary.version")
		path := tool.GetMetaString("binary.path")
		if version != "" {
			return path + " v" + version
		}
		return path
	case aitool.AIToolTypeAIExtension:
		id := tool.GetMetaString("extension.id")
		version := tool.GetMetaString("extension.version")
		ide := tool.GetMetaString("extension.ide")
		detail := id
		if version != "" {
			detail += " v" + version
		}
		if ide != "" {
			detail += " (" + ide + ")"
		}
		return detail
	case aitool.AIToolTypeProjectConfig:
		if tool.Agent != nil && len(tool.Agent.InstructionFiles) > 0 {
			return strings.Join(fileBaseNames(tool.Agent.InstructionFiles), ", ")
		}
		return tool.ConfigPath
	default:
		return tool.ConfigPath
	}
}

func writeJSONInventory(inventory *aitool.AIToolInventory, path string) error {
	data, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o644)
}

func redirectLogOutput(cmd *cobra.Command) {
	logFile, _ := cmd.Root().PersistentFlags().GetString("log")
	if logFile == "-" {
		logger.MigrateTo(os.Stdout)
	} else if logFile != "" {
		logger.LogToFile(logFile)
	} else {
		logger.MigrateTo(io.Discard)
	}
}

func fileBaseNames(paths []string) []string {
	names := make([]string, len(paths))
	for i, p := range paths {
		names[i] = filepath.Base(p)
	}
	return names
}
