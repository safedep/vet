package ai

import (
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/cmd/endpoint"
	"github.com/safedep/vet/pkg/common/logger"
)

// runAITool is overridable so tests can capture the resolved Options
// without standing up a real scan.
var runAITool = endpoint.RunAITool

func newDiscoverCommand() *cobra.Command {
	opts := endpoint.Options{
		DrainTimeout: endpoint.DefaultDrainTimeout,
	}

	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover AI tools usage, MCP servers, and coding agents",
		Long: `Alias of "vet endpoint scan --kind ai-tool". Discovers AI tools, MCP
servers, coding agents, and AI extensions on this endpoint. When SafeDep
credentials are configured the inventory is streamed to SafeDep Cloud.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			redirectLogOutput(cmd)
			return runAITool(cmd.Context(), opts)
		},
	}

	cmd.Flags().StringArrayVar(&opts.Scopes, "scope", nil,
		"Limit to specific scopes (system, project); repeatable, empty for all")
	cmd.Flags().StringVarP(&opts.ProjectDir, "project-dir", "D", "",
		"Project root for project-level discovery (default: cwd)")
	cmd.Flags().StringVar(&opts.ReportJSON, "report-json", "",
		"Write JSON inventory to file")
	cmd.Flags().BoolVarP(&opts.Silent, "silent", "s", false,
		"Suppress default summary output")
	cmd.Flags().DurationVar(&opts.DrainTimeout, "drain-timeout", endpoint.DefaultDrainTimeout,
		"Maximum time to wait for pending cloud uploads to finish on exit")

	return cmd
}

// redirectLogOutput honours the root persistent --log flag so the
// summary table on stderr stays uncluttered. Mirrors the original
// cmd/ai/discover.go behaviour byte-for-byte; the alias inherits the
// same log routing semantics users have come to rely on.
func redirectLogOutput(cmd *cobra.Command) {
	logFile, _ := cmd.Root().PersistentFlags().GetString("log")
	switch {
	case logFile == "-":
		logger.MigrateTo(os.Stdout)
	case logFile != "":
		logger.LogToFile(logFile)
	default:
		logger.MigrateTo(io.Discard)
	}
}
