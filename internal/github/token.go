// Package github gives vet a GitHub token and a GitHub API client. A GitHub
// target is a clone, and the token provider replaces "vet connect"
// (decisions D8).
package github

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ErrNoToken means that no provider has a token. vet then calls GitHub
// anonymously, with the lower rate limit.
var ErrNoToken = errors.New("github: no token")

// TokenProvider returns a GitHub token.
type TokenProvider interface {
	Token(ctx context.Context) (string, error)
}

// EnvProvider reads GITHUB_TOKEN, then GH_TOKEN.
type EnvProvider struct {
	LookupEnv func(string) (string, bool)
}

// Token returns the token of the first variable that is set.
func (p EnvProvider) Token(context.Context) (string, error) {
	_, token, err := p.find()
	return token, err
}

func (p EnvProvider) find() (name, token string, err error) {
	lookup := p.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	for _, name := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if v, ok := lookup(name); ok && strings.TrimSpace(v) != "" {
			return name, strings.TrimSpace(v), nil
		}
	}
	return "", "", ErrNoToken
}

// GHProvider runs "gh auth token".
type GHProvider struct {
	// Command replaces the gh binary, for tests.
	Command string
	Timeout time.Duration
}

// Token runs gh. A missing gh or a gh with no login is ErrNoToken.
func (p GHProvider) Token(ctx context.Context) (string, error) {
	bin := p.Command
	if bin == "" {
		bin = "gh"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return "", ErrNoToken
	}
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, path, "auth", "token")
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", ErrNoToken
	}
	token := strings.TrimSpace(out.String())
	if token == "" {
		return "", ErrNoToken
	}
	return token, nil
}

// ChainProvider returns the token of the first provider that has one.
type ChainProvider []TokenProvider

// Token tries each provider in order.
func (c ChainProvider) Token(ctx context.Context) (string, error) {
	for _, p := range c {
		t, err := p.Token(ctx)
		if err == nil {
			return t, nil
		}
		if !errors.Is(err, ErrNoToken) {
			return "", fmt.Errorf("github token: %w", err)
		}
	}
	return "", ErrNoToken
}

// DefaultProvider reads GITHUB_TOKEN, then GH_TOKEN, then "gh auth token".
func DefaultProvider() TokenProvider {
	return ChainProvider{EnvProvider{}, GHProvider{}}
}

// Source names where a provider finds its token: GITHUB_TOKEN, GH_TOKEN
// or gh auth token. It returns ErrNoToken when no provider has a token.
func Source(ctx context.Context, tp TokenProvider) (string, error) {
	switch p := tp.(type) {
	case ChainProvider:
		for _, sub := range p {
			if s, err := Source(ctx, sub); !errors.Is(err, ErrNoToken) {
				return s, err
			}
		}
		return "", ErrNoToken
	case EnvProvider:
		name, _, err := p.find()
		return name, err
	case GHProvider:
		if _, err := p.Token(ctx); err != nil {
			return "", err
		}
		return "gh auth token", nil
	}
	if _, err := tp.Token(ctx); err != nil {
		return "", err
	}
	return "the token provider", nil
}
