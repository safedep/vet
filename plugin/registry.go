package plugin

import (
	"fmt"
	"sort"
	"sync"
)

// Kind names a plugin kind.
type Kind string

const (
	KindSource       Kind = "source"
	KindExtractor    Kind = "extractor"
	KindEnricher     Kind = "enricher"
	KindControl      Kind = "control"
	KindSink         Kind = "sink"
	KindPolicySource Kind = "policy-source"
)

// Factory builds a plugin from its options.
type Factory[T any] func(Config) (T, error)

type kindRegistry[T any] struct {
	kind      Kind
	mu        sync.RWMutex
	factories map[string]Factory[T]
}

func newKindRegistry[T any](k Kind) *kindRegistry[T] {
	return &kindRegistry[T]{kind: k, factories: map[string]Factory[T]{}}
}

func (r *kindRegistry[T]) register(name string, f Factory[T]) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if name == "" || f == nil {
		panic(fmt.Sprintf("plugin: register %s with an empty name or a nil factory", r.kind))
	}
	if _, dup := r.factories[name]; dup {
		panic(fmt.Sprintf("plugin: %s %q is already registered", r.kind, name))
	}
	r.factories[name] = f
}

func (r *kindRegistry[T]) build(name string, cfg Config) (T, error) {
	r.mu.RLock()
	f, ok := r.factories[name]
	r.mu.RUnlock()
	if !ok {
		var zero T
		return zero, fmt.Errorf("plugin: no %s named %q", r.kind, name)
	}
	if cfg == nil {
		cfg = MapConfig(nil)
	}
	return f(cfg)
}

func (r *kindRegistry[T]) names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.factories))
	for n := range r.factories {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func (r *kindRegistry[T]) unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.factories, name)
}

var (
	sources       = newKindRegistry[Source](KindSource)
	extractors    = newKindRegistry[Extractor](KindExtractor)
	enrichers     = newKindRegistry[Enricher](KindEnricher)
	controls      = newKindRegistry[Control](KindControl)
	sinks         = newKindRegistry[Sink](KindSink)
	policySources = newKindRegistry[PolicySource](KindPolicySource)
)

// RegisterSource registers a source factory. It panics on a duplicate name.
func RegisterSource(name string, f Factory[Source]) { sources.register(name, f) }

// RegisterExtractor registers an extractor factory. It panics on a duplicate name.
func RegisterExtractor(name string, f Factory[Extractor]) { extractors.register(name, f) }

// RegisterEnricher registers an enricher factory. It panics on a duplicate name.
func RegisterEnricher(name string, f Factory[Enricher]) { enrichers.register(name, f) }

// RegisterControl registers a control factory. It panics on a duplicate name.
func RegisterControl(name string, f Factory[Control]) { controls.register(name, f) }

// RegisterSink registers a sink factory under its format name. It panics on
// a duplicate name.
func RegisterSink(name string, f Factory[Sink]) { sinks.register(name, f) }

// RegisterPolicySource registers a policy source factory. It panics on a
// duplicate name.
func RegisterPolicySource(name string, f Factory[PolicySource]) { policySources.register(name, f) }

// NewSource builds the named source.
func NewSource(name string, cfg Config) (Source, error) { return sources.build(name, cfg) }

// NewExtractor builds the named extractor.
func NewExtractor(name string, cfg Config) (Extractor, error) { return extractors.build(name, cfg) }

// NewEnricher builds the named enricher.
func NewEnricher(name string, cfg Config) (Enricher, error) { return enrichers.build(name, cfg) }

// NewControl builds the named control.
func NewControl(name string, cfg Config) (Control, error) { return controls.build(name, cfg) }

// NewSink builds the sink of the named format.
func NewSink(name string, cfg Config) (Sink, error) { return sinks.build(name, cfg) }

// NewPolicySource builds the named policy source.
func NewPolicySource(name string, cfg Config) (PolicySource, error) {
	return policySources.build(name, cfg)
}

// Names returns the registered names of a kind, sorted.
func Names(k Kind) []string {
	switch k {
	case KindSource:
		return sources.names()
	case KindExtractor:
		return extractors.names()
	case KindEnricher:
		return enrichers.names()
	case KindControl:
		return controls.names()
	case KindSink:
		return sinks.names()
	case KindPolicySource:
		return policySources.names()
	}
	return nil
}

// Unregister removes a registration. Tests use it to keep the registry clean.
func Unregister(k Kind, name string) {
	switch k {
	case KindSource:
		sources.unregister(name)
	case KindExtractor:
		extractors.unregister(name)
	case KindEnricher:
		enrichers.unregister(name)
	case KindControl:
		controls.unregister(name)
	case KindSink:
		sinks.unregister(name)
	case KindPolicySource:
		policySources.unregister(name)
	}
}
