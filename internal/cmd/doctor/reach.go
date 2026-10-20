package doctor

import (
	"context"
	"fmt"
	"time"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/runner"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/internal/symbols"
	"github.com/safedep/vet/v2/report"
)

// symbolDataID is the id of the check.
const symbolDataID = "reach.symbol-data"

// symbolDataCheck reads the reach of the last scan of the current
// directory: the symbol bundle and the dependency code of the call graph
// search.
func symbolDataCheck(ctx context.Context, a *app.App, f state.Flags) Check {
	doc, err := runner.Load(ctx, a, "", f)
	if err != nil {
		return Check{ID: symbolDataID, Status: Pass, Message: "no completed scan of this directory to read"}
	}
	return symbolData(doc.Header().Scan.Reach, time.Now())
}

func symbolData(r *report.ReachInfo, now time.Time) Check {
	c := Check{ID: symbolDataID, Status: Pass}
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
	if signed := r.Symbols.SignedAt; !signed.IsZero() {
		c.Message += ", signed " + signed.UTC().Format(time.DateOnly)
		if symbols.Stale(signed, now) {
			c.Status, c.Fix = Warn, "Scan with network access, or update the local bundle."
			c.Message += ", more than 7 days ago"
		}
	}
	if s := r.Sources; s != nil {
		c.Message += fmt.Sprintf(". vet found the code of %d of %d imported Go modules and Rust crates with a vulnerability", s.Found, s.Found+s.Missing)
		if s.Missing > 0 {
			c.Status, c.Fix = Warn, finding.FetchHint
		}
	}
	return c
}
