package plugin

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type nopSink struct{ opts sinkOptions }

type sinkOptions struct {
	Pretty bool `json:"pretty"`
}

func (nopSink) Write(context.Context, Report, io.Writer) error { return nil }

func TestRegistry(t *testing.T) {
	RegisterSink("test-nop", func(c Config) (Sink, error) {
		var o sinkOptions
		if err := c.Decode(&o); err != nil {
			return nil, err
		}
		return nopSink{opts: o}, nil
	})
	t.Cleanup(func() { Unregister(KindSink, "test-nop") })

	assert.Contains(t, Names(KindSink), "test-nop")

	s, err := NewSink("test-nop", MapConfig{"pretty": true})
	require.NoError(t, err)
	assert.True(t, s.(nopSink).opts.Pretty)

	_, err = NewSink("test-nop", MapConfig{"prety": true})
	assert.ErrorContains(t, err, "prety")

	_, err = NewSink("test-nop", nil)
	assert.NoError(t, err)

	_, err = NewSink("missing", nil)
	assert.ErrorContains(t, err, `no sink named "missing"`)

	assert.Panics(t, func() {
		RegisterSink("test-nop", func(Config) (Sink, error) { return nopSink{}, nil })
	})
	assert.Panics(t, func() { RegisterSink("", nil) })
}

func TestNamesPerKind(t *testing.T) {
	kinds := []Kind{KindSource, KindExtractor, KindEnricher, KindControl, KindSink, KindPolicySource}
	for _, k := range kinds {
		assert.NotNil(t, Names(k), k)
	}
	assert.Nil(t, Names("other"))
}

func TestMapConfigNil(t *testing.T) {
	var v struct{ A int }
	assert.NoError(t, MapConfig(nil).Decode(&v))
}
