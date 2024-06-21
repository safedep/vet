package exceptions

import (
	"fmt"
	"hash/fnv"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/safedep/vet/gen/exceptionsapi"
	"github.com/safedep/vet/pkg/models"
)

var (
	jitter = 5 * time.Second
)

// Represents an exception rule as per spec with additional details
type exceptionRule struct {
	spec   *exceptionsapi.Exception
	expiry time.Time
}

// In-memory store of exceptions to be used for package hash and exception ID
// based lookup for fast matching and avoid duplicates
type exceptionStore struct {
	m     sync.RWMutex
	rules map[string]map[string]*exceptionRule
}

// Represents an exceptions loader interface to support loading exceptions
// from multiple sources
type exceptionsLoader interface {
	// Read an exception rule, return io.EOF on done
	Read() (*exceptionRule, error)
}

// Represents an exception match result
type exceptionMatchResult struct {
	pkg  *models.Package
	rule *exceptionRule
}

// Global exceptions store
var globalExceptions *exceptionStore

// Initialize the global exceptions cache
func init() {
	initStore()
}

func initStore() {
	globalExceptions = &exceptionStore{
		rules: make(map[string]map[string]*exceptionRule),
	}
}

func Load(loader exceptionsLoader) error {
	globalExceptions.m.Lock()
	defer globalExceptions.m.Unlock()

	for {
		rule, err := loader.Read()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return err
			}
		}

		if rule.expiry.Before(time.Now().Add(jitter)) {
			continue
		}

		h := pkgHash(rule.spec.GetEcosystem(), rule.spec.GetName())
		if _, ok := globalExceptions.rules[h]; ok {
			if _, ok = globalExceptions.rules[h][rule.spec.GetId()]; ok {
				continue
			}
		} else {
			globalExceptions.rules[h] = make(map[string]*exceptionRule)
		}

		globalExceptions.rules[h][rule.spec.GetId()] = rule
	}

	return nil
}

func Apply(pkg *models.Package) (*exceptionMatchResult, error) {
	return globalExceptions.Match(pkg)
}

func ActiveCount() int {
	return globalExceptions.ActiveCount()
}

func (s *exceptionStore) ActiveCount() int {
	return len(s.rules)
}

func (s *exceptionStore) Match(pkg *models.Package) (*exceptionMatchResult, error) {
	result := exceptionMatchResult{}

	s.m.RLock()
	defer s.m.RUnlock()

	h := pkgHash(string(pkg.PackageDetails.Ecosystem), pkg.PackageDetails.Name)
	if _, ok := s.rules[h]; !ok {
		return &result, nil
	}

	for _, rule := range s.rules[h] {
		if rule.matchByPattern(pkg) || rule.matchByVersion(pkg) {
			result.pkg = pkg
			result.rule = rule

			return &result, nil
		}
	}

	return &result, nil
}

func (r *exceptionRule) matchByPattern(_ *models.Package) bool {
	return false
}

func (r *exceptionRule) matchByVersion(pkg *models.Package) bool {
	return strings.EqualFold(string(pkg.PackageDetails.Ecosystem), r.spec.GetEcosystem()) &&
		strings.EqualFold(pkg.PackageDetails.Name, r.spec.GetName()) &&
		((r.spec.GetVersion() == "*") || (r.spec.GetVersion() == pkg.PackageDetails.Version))
}

func (r *exceptionMatchResult) Matched() bool {
	return (r == nil) || ((r.pkg != nil) && (r.rule != nil))
}

func pkgHash(ecosystem, name string) string {
	h := fnv.New64a()
	h.Write([]byte(fmt.Sprintf("%s/%s",
		strings.ToLower(ecosystem), strings.ToLower(name))))

	return strconv.FormatUint(h.Sum64(), 16)
}
