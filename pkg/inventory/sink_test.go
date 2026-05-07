package inventory

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSessionGeneratesUUIDInvocationID(t *testing.T) {
	session := NewSession()
	require.NotNil(t, session)
	assert.NotEmpty(t, session.InvocationID)
	parsed, err := uuid.Parse(session.InvocationID)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, parsed)
}

func TestNewSessionGeneratesUniqueInvocationIDs(t *testing.T) {
	a := NewSession()
	b := NewSession()
	assert.NotEqual(t, a.InvocationID, b.InvocationID)
}

func TestNewSessionStartedAtIsRecent(t *testing.T) {
	before := time.Now()
	session := NewSession()
	after := time.Now()
	assert.False(t, session.StartedAt.Before(before),
		"StartedAt %v should not predate before %v", session.StartedAt, before)
	assert.False(t, session.StartedAt.After(after),
		"StartedAt %v should not postdate after %v", session.StartedAt, after)
}

func TestScanErrorZeroValue(t *testing.T) {
	var e ScanError
	assert.Empty(t, e.ScannerName)
	assert.Empty(t, e.ErrorType)
	assert.Empty(t, e.Message)
}

func TestScanSummaryZeroValue(t *testing.T) {
	var s ScanSummary
	assert.Equal(t, uint64(0), s.TotalObserved)
	assert.Nil(t, s.KindCounts)
	assert.Nil(t, s.Errors)
}
