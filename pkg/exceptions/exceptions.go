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
)

// Represents an exception rule as per spec with additional details
type exceptionRule struct {
	spec   *exceptionsapi.Exception
	expiry time.Time
}

// In-memory store of exceptions to be used for package hash and exception ID
// based lookup for fast matching and avoid duplicates
type exceptionStore struct {
	m     sync.Mutex
	rules map[string]map[string]*exceptionRule
}

// Represents an exceptions loader interface to support loading exceptions
// from multiple sources
type exceptionsLoader interface {
	// Read an exception rule, return io.EOF on done
	Read() (*exceptionRule, error)
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

		h := pkgHash(rule.spec.GetEcosystem(), rule.spec.GetName())
		if _, ok := globalExceptions.rules[h]; ok {
			if _, ok = globalExceptions.rules[h][rule.spec.GetId()]; ok {
				continue
			}
		} else {
			globalExceptions.rules[h] = make(map[string]*exceptionRule)
		}

		if rule.expiry.UTC().Before(time.Now().UTC()) {
			continue
		}

		globalExceptions.rules[h][rule.spec.GetId()] = rule
	}

	return nil
}

func pkgHash(ecosystem, name string) string {
	h := fnv.New64a()
	h.Write([]byte(fmt.Sprintf("%s/%s",
		strings.ToLower(ecosystem), strings.ToLower(name))))

	return strconv.FormatUint(h.Sum64(), 16)
}
