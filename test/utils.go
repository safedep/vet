package test

import (
	"os"
	"strconv"
	"testing"
)

func verifyE2E(t *testing.T) {
	s, err := strconv.ParseBool(os.Getenv("VET_E2E"))
	if (err != nil) || (!s) {
		t.Skip("E2E is disabled in the environment")
	}
}
