package github

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fixed struct {
	token string
	err   error
}

func (f fixed) Token(context.Context) (string, error) { return f.token, f.err }

func TestEnvProvider(t *testing.T) {
	cases := []struct {
		name string
		vars map[string]string
		want string
		err  error
	}{
		{"github token", map[string]string{"GITHUB_TOKEN": " ghp_a ", "GH_TOKEN": "ghp_b"}, "ghp_a", nil},
		{"gh token", map[string]string{"GH_TOKEN": "ghp_b"}, "ghp_b", nil},
		{"blank is none", map[string]string{"GITHUB_TOKEN": "  "}, "", ErrNoToken},
		{"none", nil, "", ErrNoToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := EnvProvider{LookupEnv: func(k string) (string, bool) { v, ok := tc.vars[k]; return v, ok }}
			got, err := p.Token(context.Background())
			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestChainProvider(t *testing.T) {
	ctx := context.Background()
	got, err := ChainProvider{fixed{err: ErrNoToken}, fixed{token: "t2"}}.Token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "t2", got)

	_, err = ChainProvider{fixed{err: ErrNoToken}}.Token(ctx)
	assert.ErrorIs(t, err, ErrNoToken)

	_, err = ChainProvider{fixed{err: errors.New("boom")}, fixed{token: "t2"}}.Token(ctx)
	assert.ErrorContains(t, err, "boom")
}

func TestGHProvider(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake gh is a shell script")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "gh")
	require.NoError(t, os.WriteFile(fake, []byte("#!/bin/sh\necho gho_fake\n"), 0o755))
	got, err := GHProvider{Command: fake}.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "gho_fake", got)

	failing := filepath.Join(dir, "gh-fail")
	require.NoError(t, os.WriteFile(failing, []byte("#!/bin/sh\nexit 1\n"), 0o755))
	_, err = GHProvider{Command: failing}.Token(context.Background())
	assert.ErrorIs(t, err, ErrNoToken)

	_, err = GHProvider{Command: filepath.Join(dir, "missing")}.Token(context.Background())
	assert.ErrorIs(t, err, ErrNoToken)
}

func TestNewClientUsesStubAndToken(t *testing.T) {
	var auth, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, path = r.Header.Get("Authorization"), r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"login":"octo"}`))
	}))
	t.Cleanup(srv.Close)

	c, err := NewClient(context.Background(), fixed{token: "ghp_x"}, srv.URL, srv.Client())
	require.NoError(t, err)
	u, _, err := c.Users.Get(context.Background(), "octo")
	require.NoError(t, err)
	assert.Equal(t, "octo", u.GetLogin())
	assert.Equal(t, "Bearer ghp_x", auth)
	assert.Equal(t, "/users/octo", path)

	c, err = NewClient(context.Background(), fixed{err: ErrNoToken}, "", nil)
	require.NoError(t, err)
	assert.Equal(t, "https://api.github.com/", c.BaseURL.String())
}

func TestSource(t *testing.T) {
	env := func(vars map[string]string) EnvProvider {
		return EnvProvider{LookupEnv: func(k string) (string, bool) { v, ok := vars[k]; return v, ok }}
	}
	cases := []struct {
		name string
		tp   TokenProvider
		want string
		err  error
	}{
		{"github token", ChainProvider{env(map[string]string{"GITHUB_TOKEN": "a"}), GHProvider{Command: "no-such-gh"}}, "GITHUB_TOKEN", nil},
		{"gh token", ChainProvider{env(map[string]string{"GH_TOKEN": "b"})}, "GH_TOKEN", nil},
		{"no gh", ChainProvider{env(nil), GHProvider{Command: "no-such-gh"}}, "", ErrNoToken},
		{"another provider", fixed{token: "c"}, "the token provider", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Source(context.Background(), tc.tp)
			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
