package insights

import (
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestToInsightDates(t *testing.T) {
	day := func(d int) time.Time { return time.Date(2020, 1, d, 0, 0, 0, 0, time.UTC) }
	ts := func(d int) *timestamppb.Timestamp { return timestamppb.New(day(d)) }
	version := func(v string, d int) *packagev1.PackageAvailableVersion {
		return packagev1.PackageAvailableVersion_builder{Version: v, PublishedAt: ts(d)}.Build()
	}
	cases := []struct {
		name      string
		in        *packagev1.PackageVersionInsight
		published *time.Time
		first     *time.Time
	}{
		{
			"the registry date, not the insight date",
			packagev1.PackageVersionInsight_builder{PublishedAt: ts(28), PackagePublishedAt: ts(10)}.Build(),
			new(day(10)), new(day(10)),
		},
		{
			"the earliest listed version",
			packagev1.PackageVersionInsight_builder{
				PackagePublishedAt: ts(10),
				AvailableVersions:  []*packagev1.PackageAvailableVersion{version("1.1.0", 5), version("1.0.0", 2)},
			}.Build(),
			new(day(10)), new(day(2)),
		},
		{"no dates", packagev1.PackageVersionInsight_builder{PublishedAt: ts(28)}.Build(), nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := toInsight(tc.in)
			require.NotNil(t, got)
			assert.Equal(t, tc.published, got.PublishedAt)
			assert.Equal(t, tc.first, got.FirstPublishedAt)
		})
	}
}
