package main

import (
	"context"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/safedep/dry/updater"

	"github.com/safedep/vet/pkg/common/logger"
)

const (
	vetRepoOwner = "safedep"
	vetRepoName  = "vet"
)

var yellowBold = color.New(color.Bold, color.FgYellow).SprintFunc()

// startUpdateCheck kicks off a non-blocking, asynchronous check for a newer
// vet release. It returns a channel that receives the result once the check
// completes successfully. Callers must read from the channel without blocking
// (see displayUpdateResult) so the CLI is never delayed by the network call.
//
// A nil channel is returned when the check is not applicable (e.g. dev builds);
// the nil channel is safe to pass to displayUpdateResult.
func startUpdateCheck(currentVersion string) <-chan *updater.UpdateResult {
	// Skip dev/source builds where we don't have a meaningful release version
	// to compare against.
	if currentVersion == "" || currentVersion == "(devel)" {
		return nil
	}

	checker, err := updater.NewChecker(updater.Config{
		Owner: vetRepoOwner,
		Repo:  vetRepoName,
	})
	if err != nil {
		logger.Debugf("Failed to create update checker: %v", err)
		return nil
	}

	return checker.CheckAsync(context.Background(), currentVersion)
}

// displayUpdateResult performs a non-blocking read from the update check
// channel and prints a notice if a newer version is available. If the check
// has not finished yet, it returns immediately without blocking on exit.
func displayUpdateResult(ch <-chan *updater.UpdateResult) {
	if ch == nil {
		return
	}

	select {
	case result := <-ch:
		if result != nil && result.UpdateAvailable {
			printUpdateNotice(result)
		}
	default:
		// Check not finished yet; do not block the CLI from exiting.
	}
}

// printUpdateNotice writes the update notice to stderr so it never corrupts
// machine-readable output (JSON, SARIF, etc.) emitted on stdout.
func printUpdateNotice(result *updater.UpdateResult) {
	fmt.Fprintf(os.Stderr, "\n%s %s → %s\n%s\n",
		yellowBold("A new version of vet is available:"),
		whiteDim(result.CurrentVersion),
		whiteBold(result.LatestVersion),
		whiteDim(result.ReleaseURL),
	)
}
