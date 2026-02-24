package code

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect/sql"

	"github.com/safedep/vet/ent"
	"github.com/safedep/vet/ent/codesignaturematch"
	"github.com/safedep/vet/ent/predicate"
)

// SignatureMatchFilter describes the filter criteria for querying
// signature matches from the database.
type SignatureMatchFilter struct {
	Tags          []string // OR: match has at least one of these tags
	Languages     []string // OR: match language is one of these
	Vendors       []string // OR: match vendor is one of these
	Products      []string // OR: match product is one of these
	Services      []string // OR: match service is one of these
	FileSubstring string   // case-insensitive substring match on file_path
	Limit         int      // max rows to return (0 = unlimited)
}

// SignatureMatchQueryResult holds the query results along with the
// total count of matches (before limit is applied).
type SignatureMatchQueryResult struct {
	Matches    []*ent.CodeSignatureMatch
	TotalCount int
}

// QueryRepository provides filtered, paginated queries for code scan data.
type QueryRepository interface {
	QuerySignatureMatches(ctx context.Context, filter SignatureMatchFilter) (*SignatureMatchQueryResult, error)
}

type queryRepositoryImpl struct {
	client *ent.Client
}

// NewQueryRepository creates a new QueryRepository backed by the given ent client.
func NewQueryRepository(client *ent.Client) QueryRepository {
	return &queryRepositoryImpl{client: client}
}

func (r *queryRepositoryImpl) QuerySignatureMatches(ctx context.Context, filter SignatureMatchFilter) (*SignatureMatchQueryResult, error) {
	predicates := buildPredicates(filter)

	// Count total matches (before limit)
	countQuery := r.client.CodeSignatureMatch.Query()
	if len(predicates) > 0 {
		countQuery = countQuery.Where(codesignaturematch.And(predicates...))
	}

	totalCount, err := countQuery.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to count signature matches: %w", err)
	}

	// Fetch with limit
	fetchQuery := r.client.CodeSignatureMatch.Query()
	if len(predicates) > 0 {
		fetchQuery = fetchQuery.Where(codesignaturematch.And(predicates...))
	}

	fetchQuery = fetchQuery.Order(codesignaturematch.ByID())
	if filter.Limit > 0 {
		fetchQuery = fetchQuery.Limit(filter.Limit)
	}

	matches, err := fetchQuery.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch signature matches: %w", err)
	}

	return &SignatureMatchQueryResult{
		Matches:    matches,
		TotalCount: totalCount,
	}, nil
}

func buildPredicates(filter SignatureMatchFilter) []predicate.CodeSignatureMatch {
	var predicates []predicate.CodeSignatureMatch

	if len(filter.Languages) > 0 {
		langPredicates := make([]predicate.CodeSignatureMatch, len(filter.Languages))
		for i, lang := range filter.Languages {
			langPredicates[i] = codesignaturematch.LanguageEqualFold(lang)
		}
		predicates = append(predicates, codesignaturematch.Or(langPredicates...))
	}

	if len(filter.Vendors) > 0 {
		vendorPredicates := make([]predicate.CodeSignatureMatch, len(filter.Vendors))
		for i, v := range filter.Vendors {
			vendorPredicates[i] = codesignaturematch.SignatureVendorEqualFold(v)
		}
		predicates = append(predicates, codesignaturematch.Or(vendorPredicates...))
	}

	if len(filter.Products) > 0 {
		productPredicates := make([]predicate.CodeSignatureMatch, len(filter.Products))
		for i, p := range filter.Products {
			productPredicates[i] = codesignaturematch.SignatureProductEqualFold(p)
		}
		predicates = append(predicates, codesignaturematch.Or(productPredicates...))
	}

	if len(filter.Services) > 0 {
		servicePredicates := make([]predicate.CodeSignatureMatch, len(filter.Services))
		for i, s := range filter.Services {
			servicePredicates[i] = codesignaturematch.SignatureServiceEqualFold(s)
		}
		predicates = append(predicates, codesignaturematch.Or(servicePredicates...))
	}

	if filter.FileSubstring != "" {
		predicates = append(predicates, codesignaturematch.FilePathContainsFold(filter.FileSubstring))
	}

	if len(filter.Tags) > 0 {
		predicates = append(predicates, tagContainsAny(filter.Tags))
	}

	return predicates
}

// tagContainsAny builds an ent predicate that checks whether the JSON
// tags column contains at least one of the given tag values.
// Tags are stored as a JSON array e.g. ["ai","llm"]. We use ent's
// sql.ContainsFold to do a case-insensitive LIKE match for each tag
// value (with JSON quotes) inside the serialised array.
func tagContainsAny(tags []string) predicate.CodeSignatureMatch {
	return predicate.CodeSignatureMatch(func(s *sql.Selector) {
		col := s.C(codesignaturematch.FieldTags)

		tagPreds := make([]*sql.Predicate, len(tags))
		for i, tag := range tags {
			// Match the JSON-encoded tag value inside the array.
			// Searching for `"ai"` (with quotes) within `["ai","llm"]`
			// avoids false positives on partial matches.
			tagPreds[i] = sql.ContainsFold(col, fmt.Sprintf(`"%s"`, tag))
		}

		s.Where(sql.Or(tagPreds...))
	})
}
