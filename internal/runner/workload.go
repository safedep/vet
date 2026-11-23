package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/safedep/vet/v2/internal/credentials"
	"github.com/safedep/vet/v2/internal/tui"
	"github.com/safedep/vet/v2/report"
)

// CodeWorkloadExchange is the diagnostic code of a workload identity
// exchange that failed. The scan then makes no call to SafeDep Cloud.
const CodeWorkloadExchange = "workload_exchange_failed"

// revokeTimeout bounds the revocation of the workload credential at the
// end of a run, so that an unreachable SafeDep Cloud does not hold the job.
const revokeTimeout = 10 * time.Second

// exchangeDiagnostics runs the first workload identity exchange of a run.
// A failed exchange does not stop the scan: it is a diagnostic, and the
// scan makes no call to SafeDep Cloud.
func exchangeDiagnostics(ctx context.Context, creds *credentials.Result) ([]*report.Diagnostic, error) {
	err := creds.Exchange(ctx)
	if err == nil {
		return nil, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return []*report.Diagnostic{{
		Level: report.DiagnosticWarning, Code: CodeWorkloadExchange, Component: "credentials",
		Message: fmt.Sprintf("vet did not get a SafeDep Cloud credential of tenant %s for the workload identity of the job, "+
			"so the scan uses no SafeDep Cloud data and sends nothing to SafeDep Cloud. The error is: %v", creds.TenantDomain(), err),
	}}, nil
}

// RevokeWorkload revokes the workload credential of a run, so that the
// credential does not outlive the job. It also runs after a stop on a
// signal, so it does not use the cancellation of ctx.
func RevokeWorkload(ctx context.Context, creds *credentials.Result) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revokeTimeout)
	defer cancel()
	if err := creds.Revoke(ctx); err != nil {
		tui.Warning("vet could not revoke the SafeDep Cloud credential of the job. The credential expires by itself. The error is: %v", err)
	}
}
