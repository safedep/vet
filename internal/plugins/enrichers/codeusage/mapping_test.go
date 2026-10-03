package codeusage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
)

func TestProvides(t *testing.T) {
	pv := provider{autoload: map[string]string{`GuzzleHttp\`: "guzzlehttp/guzzle", `GuzzleHttp\Psr7\`: "guzzlehttp/psr7"}}
	id := func(eco model.Ecosystem, namespace, name string) model.PackageID {
		return model.PackageID{Ecosystem: eco, Namespace: namespace, Name: name, Version: "1"}
	}
	cases := []struct {
		name string
		id   model.PackageID
		m    module
		want bool
	}{
		{"npm hint", id(model.EcosystemNpm, "", "lodash"), module{"javascript", "lodash", "lodash/fp"}, true},
		{"npm scope", id(model.EcosystemNpm, "@scope", "pkg"), module{"typescript", "@scope/pkg", "@scope/pkg/sub"}, true},
		{"language must fit", id(model.EcosystemNpm, "", "requests"), module{"python", "requests", "requests"}, false},
		{"evidence with no language", id(model.EcosystemNpm, "", "a"), module{"", "a", "a"}, true},
		{"pypi underscore", id(model.EcosystemPyPI, "", "python-dateutil"), module{"python", "python_dateutil", "dateutil"}, true},
		{"pypi namespace package", id(model.EcosystemPyPI, "", "google-cloud-storage"), module{"python", "google", "google.cloud.storage.blob"}, true},
		{"pypi other namespace package", id(model.EcosystemPyPI, "", "google-cloud-pubsub"), module{"python", "google", "google.cloud.storage"}, false},
		{"maven group", id(model.EcosystemMaven, "org.springframework.ai", "spring-ai-openai"), module{"java", "", "org.springframework.ai.chat.client.ChatClient"}, true},
		{"maven kotlin", id(model.EcosystemMaven, "com.squareup.okhttp3", "okhttp"), module{"kotlin", "", "com.squareup.okhttp3"}, true},
		{"maven other group", id(model.EcosystemMaven, "org.springframework.boot", "spring-boot"), module{"java", "", "org.springframework.ai.chat.ChatClient"}, false},
		{"nuget namespace", id(model.EcosystemNuGet, "", "Newtonsoft.Json"), module{"csharp", "Newtonsoft.Json.Linq", "Newtonsoft.Json.Linq"}, true},
		{"nuget abstractions", id(model.EcosystemNuGet, "", "Microsoft.Extensions.Logging.Abstractions"), module{"csharp", "Microsoft.Extensions.Logging", "Microsoft.Extensions.Logging"}, true},
		{"nuget wide namespace", id(model.EcosystemNuGet, "", "System.Text.Json"), module{"csharp", "System", "System"}, false},
		{"cargo dash", id(model.EcosystemCargo, "", "async-openai"), module{"rust", "async_openai", "async_openai::types"}, true},
		{"gem hint", id(model.EcosystemRubyGems, "", "ruby-openai"), module{"ruby", "ruby-openai", "openai"}, true},
		{"gem path", id(model.EcosystemRubyGems, "", "rspec-core"), module{"ruby", "rspec", "rspec/core"}, true},
		{"go module", id(model.EcosystemGo, "", "github.com/sashabaranov/go-openai"), module{"go", "github.com/sashabaranov/go-openai", "github.com/sashabaranov/go-openai/jsonschema"}, true},
		{"composer autoload", id(model.EcosystemPackagist, "guzzlehttp", "psr7"), module{"php", "", `GuzzleHttp\Psr7\Response`}, true},
		{"composer longest prefix", id(model.EcosystemPackagist, "guzzlehttp", "guzzle"), module{"php", "", `GuzzleHttp\Psr7\Response`}, false},
		{"composer leading separator", id(model.EcosystemPackagist, "guzzlehttp", "guzzle"), module{"php", "", `\GuzzleHttp\Client`}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, pv.provides(c.id, c.m))
		})
	}
}

func TestReadAutoload(t *testing.T) {
	dir := t.TempDir()
	lock := `{"packages":[{"name":"openai-php/client","autoload":{"psr-4":{"OpenAI\\":"src/"}}}],
		"packages-dev":[{"name":"Mockery/Mockery","autoload":{"psr-0":{"Mockery":"library/"}}}]}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(lock), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "vendor", "x"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "vendor", "x", "composer.lock"), []byte(`{"packages":[{"name":"skipped/pkg","autoload":{"psr-4":{"Skipped\\":"src/"}}}]}`), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "bad"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad", "composer.lock"), []byte("{"), 0o600))

	autoload, err := readAutoload(dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{`OpenAI\`: "openai-php/client", `Mockery\`: "mockery/mockery"}, autoload)
}
