package doctor

import (
	"context"
	"fmt"
	"time"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/runner"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/report"
)

// symbolDataStale is the age of a symbol bundle that the check warns about.
// It is the same age as the warning of a scan.
const symbolDataStale = 7 * 24 * time.Hour

// symbolDataCheck reads the reach of the last scan of the current
// directory: the symbol bundle and the dependency code of the call graph
// search.
func symbolDataCheck(ctx context.Context, a *app.App, f state.Flags) Check {
	doc, err := runner.Load(ctx, a, "", f)
	if err != nil {
		return Check{ID: "reach.symbol-data", Status: Pass, Message: "no completed scan of this directory to read"}
	}
	return symbolData(doc.Header().Scan.Reach, time.Now())
}

func symbolData(r *report.ReachInfo, now time.Time) Check {
	c := Check{ID: "reach.symbol-data", Status: Pass}
	switch {
	case r == nil || r.Level != report.ReachFunction || r.Status != report.ReachComputed:
		c.Message = "the last scan computed no function reach"
		return c
	case r.Symbols == nil:
		c.Status, c.Message = Warn, "the last scan had no symbol data"
		c.Fix = "Scan with network access, or set plugins.codeusage.options.symbols_bundle."
		return c
	}
	c.Message = fmt.Sprintf("the last scan read symbol bundle %s with %d records", r.Symbols.ID, r.Symbols.Records)
	if !r.Symbols.SignedAt.IsZero() && now.Sub(r.Symbols.SignedAt) > symbolDataStale {
		c.Status, c.Fix = Warn, "Scan with network access, or update the local bundle."
		c.Message += fmt.Sprintf(", signed %s, more than 7 days ago", r.Symbols.SignedAt.UTC().Format(time.DateOnly))
	}
	if s := r.Sources; s != nil {
		c.Message += fmt.Sprintf(". vet found the code of %d of %d imported Go modules and Rust crates with a vulnerability", s.Found, s.Found+s.Missing)
		if s.Missing > 0 {
			c.Status, c.Fix = Warn, "Run go mod download or cargo fetch, then scan again."
		}
	}
	return c
}
