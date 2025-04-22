package analytics

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/posthog/posthog-go"
)

const (
	postHogApiKey        = "phc_ckrojb22DtoIMBhIC3k3hh7tmRw0ng11gSaLUXSqwSt" // gitleaks:allow
	postHogEventEndpoint = "https://us.i.posthog.com"

	telemetryDisableEnvKey = "VET_DISABLE_TELEMETRY"
)

var (
	globalPosthogClient posthog.Client

	// This is the distinct ID to anonymously identify an invocation of the CLI.
	globalDistinctId string
)

func init() {
	if isTelemetryDisabled() {
		return
	}

	client, err := posthog.NewWithConfig(postHogApiKey, posthog.Config{
		Endpoint: postHogEventEndpoint,
	})
	if err != nil {
		log.Fatalf("Failed to initialize posthog client: %v", err)
	}

	globalPosthogClient = client

	randomUUID, err := uuid.NewRandom()
	if err != nil {
		log.Fatalf("Failed to generate random UUID: %v", err)
	}

	globalDistinctId = randomUUID.String()
}

func isTelemetryDisabled() bool {
	val := os.Getenv(telemetryDisableEnvKey)
	if booleanVal, err := strconv.ParseBool(val); err == nil {
		return booleanVal
	}

	return false
}

func IsDisabled() bool {
	return isTelemetryDisabled()
}

// We want to ensure that we do not collect any telemetry if the user has disabled them.
// This is a helper function to ensure that we do not collect any telemetry if the user has disabled them.
func Track(distinctId string, event string, properties posthog.Properties) {
	if isTelemetryDisabled() {
		return
	}

	if globalPosthogClient == nil {
		return
	}

	_ = globalPosthogClient.Enqueue(&posthog.Capture{
		DistinctId: distinctId,
		Event:      event,
		Properties: properties,
		Timestamp:  time.Now(),
	})
}

func TrackEvent(event string) {
	Track(globalDistinctId, event,
		posthog.NewProperties().
			Set("$process_person_profile", false))
}

func Close() {
	if globalPosthogClient == nil {
		return
	}

	_ = globalPosthogClient.Close()
	globalPosthogClient = nil
}
