package code

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/internal/command"
	pkgcode "github.com/safedep/vet/pkg/code"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/storage"
	xbomtui "github.com/safedep/vet/pkg/xbom/tui"
)

var (
	queryDBPath        string
	queryTags          []string
	queryLanguages     []string
	queryVendors       []string
	queryProducts      []string
	queryServices      []string
	queryFileSubstring string
	queryLimit         int
)

func newQueryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query code scan results from the database",
		RunE: func(cmd *cobra.Command, args []string) error {
			startQuery()
			return nil
		},
	}

	cmd.Flags().StringVar(&queryDBPath, "db", "", "Path to the sqlite database produced by code scan")
	cmd.Flags().StringArrayVar(&queryTags, "tag", []string{}, "Filter by tag (e.g. --tag ai --tag crypto)")
	cmd.Flags().StringArrayVar(&queryLanguages, "language", []string{}, "Filter by language (e.g. --language go)")
	cmd.Flags().StringArrayVar(&queryVendors, "vendor", []string{}, "Filter by signature vendor")
	cmd.Flags().StringArrayVar(&queryProducts, "product", []string{}, "Filter by signature product")
	cmd.Flags().StringArrayVar(&queryServices, "service", []string{}, "Filter by signature service")
	cmd.Flags().StringVar(&queryFileSubstring, "file", "", "Filter by file path substring (case-insensitive)")
	cmd.Flags().IntVar(&queryLimit, "limit", 50, "Maximum number of results to display (0 for unlimited)")

	_ = cmd.MarkFlagRequired("db")

	return cmd
}

func startQuery() {
	command.FailOnError("code query", internalStartQuery())
}

func internalStartQuery() error {
	entSqliteStorage, err := storage.NewEntSqliteStorage(storage.EntSqliteClientConfig{
		Path:               queryDBPath,
		ReadOnly:           true,
		SkipSchemaCreation: true,
	})
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() {
		if err := entSqliteStorage.Close(); err != nil {
			logger.Warnf("failed to close storage: %v", err)
		}
	}()

	client, err := entSqliteStorage.Client()
	if err != nil {
		return fmt.Errorf("failed to get database client: %w", err)
	}

	repo := pkgcode.NewQueryRepository(client)

	result, err := repo.QuerySignatureMatches(context.Background(), pkgcode.SignatureMatchFilter{
		Tags:          queryTags,
		Languages:     queryLanguages,
		Vendors:       queryVendors,
		Products:      queryProducts,
		Services:      queryServices,
		FileSubstring: queryFileSubstring,
		Limit:         queryLimit,
	})
	if err != nil {
		return fmt.Errorf("failed to query signature matches: %w", err)
	}

	renderer := xbomtui.NewQueryResultRenderer()
	fmt.Print(renderer.RenderMatches(result.Matches, result.TotalCount))

	return nil
}
