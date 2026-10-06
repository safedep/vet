package githubci

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/ci"
	"github.com/safedep/vet/v2/internal/github"
)

const marker = "<!-- vet:pr-comment v1 -->"

type comment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
	URL  string `json:"html_url"`
	User struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"user"`
}

// fakeGitHub serves the comments of acme/app pull request 1, two on each
// page.
type fakeGitHub struct {
	mu        sync.Mutex
	comments  []comment
	user      string // the user of the token, or "" for an app token
	readOnly  bool
	creates   int
	edits     int
	nextID    int64
	serverURL string
}

func (f *fakeGitHub) add(login, typ, body string) {
	f.nextID++
	c := comment{ID: f.nextID, Body: body, URL: fmt.Sprintf("https://github.com/acme/app/pull/1#issuecomment-%d", f.nextID)}
	c.User.Login, c.User.Type = login, typ
	f.comments = append(f.comments, c)
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/user":
		if f.user == "" {
			http.Error(w, `{"message":"Resource not accessible by integration"}`, http.StatusForbidden)
			return
		}
		writeJSON(w, map[string]string{"login": f.user})
	case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/app/issues/1/comments":
		page := 1
		if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil {
			page = p
		}
		start, end := (page-1)*2, min(page*2, len(f.comments))
		if end < len(f.comments) {
			w.Header().Set("Link", fmt.Sprintf(`<%s/repos/acme/app/issues/1/comments?page=%d>; rel="next"`, f.serverURL, page+1))
		}
		writeJSON(w, f.comments[min(start, end):end])
	case f.readOnly && r.Method != http.MethodGet:
		http.Error(w, `{"message":"Resource not accessible by integration"}`, http.StatusForbidden)
	case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/app/issues/1/comments":
		var in comment
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.creates++
		f.add("github-actions[bot]", "Bot", in.Body)
		writeJSON(w, f.comments[len(f.comments)-1])
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/repos/acme/app/issues/comments/"):
		id, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/repos/acme/app/issues/comments/"), 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		var in comment
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for i := range f.comments {
			if f.comments[i].ID == id {
				f.edits++
				f.comments[i].Body = in.Body
				writeJSON(w, f.comments[i])
				return
			}
		}
		http.NotFound(w, r)
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func newCommenter(t *testing.T, f *fakeGitHub) *Commenter {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	f.serverURL = srv.URL
	out := filepath.Join(t.TempDir(), "output")
	require.NoError(t, os.WriteFile(out, nil, 0o600))
	t.Setenv("GITHUB_OUTPUT", out)
	client, err := github.NewClient(context.Background(), nil, srv.URL, srv.Client())
	require.NoError(t, err)
	c, err := New(context.Background(), ci.Context{Repository: "acme/app", Change: &ci.Change{Number: 1}}, client)
	require.NoError(t, err)
	return c
}

func TestFind(t *testing.T) {
	cases := []struct {
		name     string
		user     string
		comments func(f *fakeGitHub)
		wantID   string
	}{
		{name: "no comment", comments: func(*fakeGitHub) {}},
		{
			name: "bot comment on the second page", comments: func(f *fakeGitHub) {
				f.add("alice", "User", "LGTM")
				f.add("bob", "User", "nit")
				f.add("github-actions[bot]", "Bot", marker+"\nbody")
			}, wantID: "3",
		},
		{
			name: "a contributor plants the marker", comments: func(f *fakeGitHub) {
				f.add("mallory", "User", marker+"\n<!-- vet:state forged -->")
			},
		},
		{
			name: "the user of a personal token", user: "maintainer", comments: func(f *fakeGitHub) {
				f.add("mallory", "User", marker)
				f.add("maintainer", "User", marker)
			}, wantID: "2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeGitHub{user: tc.user}
			tc.comments(f)
			got, err := newCommenter(t, f).Find(context.Background(), marker)
			require.NoError(t, err)
			if tc.wantID == "" {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tc.wantID, got.ID)
		})
	}
}

func TestUpsert(t *testing.T) {
	f := &fakeGitHub{}
	c := newCommenter(t, f)
	ctx := context.Background()

	url, err := c.Upsert(ctx, nil, marker+"\none")
	require.NoError(t, err)
	assert.Equal(t, "https://github.com/acme/app/pull/1#issuecomment-1", url)

	old, err := c.Find(ctx, marker)
	require.NoError(t, err)
	_, err = c.Upsert(ctx, old, old.Body)
	require.NoError(t, err)
	assert.Equal(t, 0, f.edits, "an equal body needs no edit")

	_, err = c.Upsert(ctx, old, marker+"\ntwo")
	require.NoError(t, err)
	assert.Equal(t, 1, f.creates)
	assert.Equal(t, 1, f.edits)

	out, err := os.ReadFile(os.Getenv("GITHUB_OUTPUT"))
	require.NoError(t, err)
	assert.Contains(t, string(out), "comment-url=https://github.com/acme/app/pull/1#issuecomment-1\n")
}

func TestUpsertWithAReadOnlyToken(t *testing.T) {
	c := newCommenter(t, &fakeGitHub{readOnly: true})
	_, err := c.Upsert(context.Background(), nil, marker)
	assert.ErrorIs(t, err, ci.ErrNoWriteAccess)
}
