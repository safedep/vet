// Package stub is the stub SafeDep server of the acceptance suite. It
// answers Insights v2, Malysis and the GitHub API from fixture files, and
// it never calls the network (acceptance suite design, section 3.3).
package stub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	insightsv2grpc "buf.build/gen/go/safedep/api/grpc/go/safedep/services/insights/v2/insightsv2grpc"
	malysisv1grpc "buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	malysismsg "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	insightsv2 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/insights/v2"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// The services of the stub, for Fail and Calls.
const (
	Insights = "insights"
	Malysis  = "malysis"
	GitHub   = "github"
	// Other counts the gRPC calls of a service that the stub does not
	// serve, such as an upload.
	Other = "other"
	// Authenticated counts the requests that carry an authorization header.
	Authenticated = "authenticated"
)

// Server is one stub server. The harness starts one for each script.
type Server struct {
	dir  string
	ln   net.Listener
	http *http.Server
	grpc *grpc.Server

	closeOnce sync.Once
	closeErr  error

	mu    sync.Mutex
	delay time.Duration
	fail  map[string]codes.Code
	calls map[string]int
}

// Start serves the fixtures under dir on a free local port. gRPC and the
// GitHub API share the port: gRPC over unencrypted HTTP/2, the GitHub API
// over HTTP/1.1.
func Start(dir string) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{dir: dir, ln: ln, fail: map[string]codes.Code{}, calls: map[string]int{}}
	s.grpc = grpc.NewServer(grpc.UnknownServiceHandler(func(any, grpc.ServerStream) error {
		s.count(Other)
		return status.Error(codes.Unimplemented, "stub: no such service")
	}))
	insightsv2grpc.RegisterInsightServiceServer(s.grpc, &insightService{s: s})
	malysisv1grpc.RegisterMalwareAnalysisServiceServer(s.grpc, &malysisService{s: s})

	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	s.http = &http.Server{Handler: s, Protocols: &protocols, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := s.http.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "stub: serve: %v\n", err)
		}
	}()
	return s, nil
}

// URL returns the base URL of the server, for example http://127.0.0.1:4711.
func (s *Server) URL() string { return "http://" + s.ln.Addr().String() }

// Close stops the server. A stopped server refuses each connection. A
// second Close does nothing.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.grpc.Stop()
		s.closeErr = s.http.Close()
	})
	return s.closeErr
}

// SetDelay slows each answer, so that a script can stop a scan in the
// middle.
func (s *Server) SetDelay(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delay = d
}

// Fail makes each call of a service fail with a gRPC code. For the GitHub
// API the stub answers HTTP 503. codes.OK removes the failure.
func (s *Server) Fail(service string, code codes.Code) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if code == codes.OK {
		delete(s.fail, service)
		return
	}
	s.fail[service] = code
}

// Calls returns the number of calls of a service.
func (s *Server) Calls(service string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[service]
}

func (s *Server) count(service string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[service]++
}

// begin counts a call, waits for the delay and returns the failure of the
// service.
func (s *Server) begin(ctx context.Context, service string) error {
	s.mu.Lock()
	s.calls[service]++
	delay, code := s.delay, s.fail[service]
	s.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if code != codes.OK {
		return status.Errorf(code, "stub: %s fails", service)
	}
	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "" {
		s.count(Authenticated)
	}
	if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
		s.grpc.ServeHTTP(w, r)
		return
	}
	s.serveGitHub(w, r)
}

// fixturePath returns the fixture of a package version:
// <service>/<ecosystem>/<name>@<version>.json. The ecosystem is the enum
// name without its prefix, in lower case. A ":" in a name becomes "_".
func (s *Server) fixturePath(service string, pv *packagev1.PackageVersion) string {
	eco := strings.ToLower(strings.TrimPrefix(pv.GetPackage().GetEcosystem().String(), "ECOSYSTEM_"))
	name := strings.ReplaceAll(pv.GetPackage().GetName(), ":", "_")
	return s.fixture(service, eco, filepath.FromSlash(name)+"@"+pv.GetVersion()+".json")
}

// fixture returns the file under the fixture directory, or "" when the
// parts of the request path leave the directory.
func (s *Server) fixture(parts ...string) string {
	rel := filepath.Join(parts...)
	if !filepath.IsLocal(rel) || strings.Contains(rel, "..") {
		return ""
	}
	return filepath.Join(s.dir, rel)
}

// readFixture decodes a protojson fixture. It returns false when the file
// does not exist.
func readFixture(path string, m proto.Message) (bool, error) {
	if path == "" {
		return false, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := protojson.Unmarshal(data, m); err != nil {
		return false, fmt.Errorf("stub: fixture %s: %w", path, err)
	}
	return true, nil
}

type insightService struct {
	insightsv2grpc.UnimplementedInsightServiceServer
	s *Server
}

// GetPackageVersionInsight answers from the fixture. An unknown package
// version is NotFound.
func (i *insightService) GetPackageVersionInsight(ctx context.Context, req *insightsv2.GetPackageVersionInsightRequest) (*insightsv2.GetPackageVersionInsightResponse, error) {
	if err := i.s.begin(ctx, Insights); err != nil {
		return nil, err
	}
	res := &insightsv2.GetPackageVersionInsightResponse{}
	found, err := readFixture(i.s.fixturePath(Insights, req.GetPackageVersion()), res)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	// A registry keys a package by its exact name and version. The fixture
	// names its package, so the stub matches it exactly, also on a file
	// system that ignores the case of a path.
	if got := res.GetPackageVersion(); found && got != nil &&
		(got.GetPackage().GetName() != req.GetPackageVersion().GetPackage().GetName() || got.GetVersion() != req.GetPackageVersion().GetVersion()) {
		found = false
	}
	if !found {
		return nil, status.Errorf(codes.NotFound, "stub: no insight for %s@%s",
			req.GetPackageVersion().GetPackage().GetName(), req.GetPackageVersion().GetVersion())
	}
	if res.PackageVersion == nil {
		res.PackageVersion = req.GetPackageVersion()
	}
	return res, nil
}

type malysisService struct {
	malysisv1grpc.UnimplementedMalwareAnalysisServiceServer
	s *Server
}

// QueryPackageAnalysis answers from the fixture. The default answer is a
// completed analysis that found no malware.
func (m *malysisService) QueryPackageAnalysis(ctx context.Context, req *malysisv1.QueryPackageAnalysisRequest) (*malysisv1.QueryPackageAnalysisResponse, error) {
	if err := m.s.begin(ctx, Malysis); err != nil {
		return nil, err
	}
	pv := req.GetTarget().GetPackageVersion()
	res := &malysisv1.QueryPackageAnalysisResponse{}
	found, err := readFixture(m.s.fixturePath(Malysis, pv), res)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if !found {
		res = &malysisv1.QueryPackageAnalysisResponse{
			AnalysisId: "stub-clean",
			Status:     malysisv1.AnalysisStatus_ANALYSIS_STATUS_COMPLETED,
			Report: &malysismsg.Report{
				PackageVersion: pv,
				Inference:      &malysismsg.Report_Inference{IsMalware: false, Summary: "stub: no malware"},
			},
		}
	}
	return res, nil
}

// githubRepo is the fixture of one repository: the commit SHA of each tag
// and branch, the release tags, newest first, the default branch (main
// when empty), and the status of each compare base...head that is not
// identical or diverged.
type githubRepo struct {
	Tags          map[string]string `json:"tags"`
	Branches      map[string]string `json:"branches"`
	Releases      []string          `json:"releases"`
	DefaultBranch string            `json:"default_branch"`
	Compare       map[string]string `json:"compare"`
}

// serveGitHub answers the GitHub API calls that resolve a ref to a commit
// SHA, from github/<owner>/<repo>.json:
//
//	GET /repos/{owner}/{repo}/git/ref/tags/{tag}
//	GET /repos/{owner}/{repo}/git/ref/heads/{branch}
//	GET /repos/{owner}/{repo}/commits/{ref}
//	GET /repos/{owner}/{repo}/releases (one page)
//	GET /repos/{owner}/{repo}
//	GET /repos/{owner}/{repo}/tags and /branches (one page)
//	GET /repos/{owner}/{repo}/compare/{base}...{head}
func (s *Server) serveGitHub(w http.ResponseWriter, r *http.Request) {
	if err := s.begin(r.Context(), GitHub); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v3"), "/"), "/")
	if r.Method == http.MethodGet && len(parts) == 4 && parts[0] == "repos" && parts[3] == "releases" {
		s.serveReleases(w, r, parts[1], parts[2])
		return
	}
	if r.Method != http.MethodGet || len(parts) < 3 || parts[0] != "repos" {
		http.NotFound(w, r)
		return
	}
	var repo githubRepo
	path := s.fixture(GitHub, parts[1], parts[2]+".json")
	if path == "" {
		http.NotFound(w, r)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := json.Unmarshal(data, &repo); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rest := parts[3:]
	if len(rest) == 0 || rest[0] == "tags" || rest[0] == "branches" || rest[0] == "compare" {
		serveRepo(w, r, &repo, rest)
		return
	}
	var sha, ref string
	switch {
	case len(rest) >= 4 && rest[0] == "git" && rest[1] == "ref" && rest[2] == "tags":
		ref = strings.Join(rest[3:], "/")
		sha, ref = repo.Tags[ref], "refs/tags/"+ref
	case len(rest) >= 4 && rest[0] == "git" && rest[1] == "ref" && rest[2] == "heads":
		ref = strings.Join(rest[3:], "/")
		sha, ref = repo.Branches[ref], "refs/heads/"+ref
	case len(rest) >= 2 && rest[0] == "commits":
		ref = strings.Join(rest[1:], "/")
		sha = repo.Tags[ref]
		if sha == "" {
			sha = repo.Branches[ref]
		}
	}
	if sha == "" {
		http.NotFound(w, r)
		return
	}
	if rest[0] == "commits" && strings.Contains(r.Header.Get("Accept"), "sha") {
		if _, err := fmt.Fprint(w, sha); err != nil {
			fmt.Fprintf(os.Stderr, "stub: write: %v\n", err)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	body := map[string]any{"sha": sha}
	if rest[0] == "git" {
		body = map[string]any{"ref": ref, "object": map[string]string{"sha": sha, "type": "commit"}}
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// serveRepo answers the calls of the actionrefs enricher: the repository,
// its tags and branches, and the compare of a ref with a commit.
func serveRepo(w http.ResponseWriter, r *http.Request, repo *githubRepo, rest []string) {
	var body any
	switch {
	case len(rest) == 0:
		def := repo.DefaultBranch
		if def == "" {
			def = "main"
		}
		body = map[string]string{"default_branch": def}
	case len(rest) == 1 && rest[0] == "tags":
		body = refList(repo.Tags)
	case len(rest) == 1 && rest[0] == "branches":
		body = refList(repo.Branches)
	case rest[0] == "compare":
		pair := strings.Join(rest[1:], "/")
		base, head, _ := strings.Cut(pair, "...")
		status := repo.Compare[pair]
		switch {
		case status == "notfound":
			http.NotFound(w, r)
			return
		case status != "":
		case repo.Branches[base] == head || repo.Tags[base] == head:
			status = "identical"
		default:
			status = "diverged"
		}
		body = map[string]string{"status": status}
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		fmt.Fprintf(os.Stderr, "stub: write: %v\n", err)
	}
}

// refList returns the tags or the branches of a fixture in name order.
func refList(refs map[string]string) []map[string]any {
	out := make([]map[string]any, 0, len(refs))
	for _, name := range slices.Sorted(maps.Keys(refs)) {
		out = append(out, map[string]any{"name": name, "commit": map[string]string{"sha": refs[name]}})
	}
	return out
}

// serveReleases answers the release list of a repository from the
// releases of its fixture. The list fits on one page.
func (s *Server) serveReleases(w http.ResponseWriter, r *http.Request, owner, name string) {
	path := s.fixture(GitHub, owner, name+".json")
	data, err := os.ReadFile(path)
	if path == "" || err != nil {
		http.NotFound(w, r)
		return
	}
	var repo githubRepo
	if err := json.Unmarshal(data, &repo); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type release struct {
		TagName string `json:"tag_name"`
	}
	out := make([]release, 0, len(repo.Releases))
	for _, tag := range repo.Releases {
		out = append(out, release{TagName: tag})
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "stub: write: %v\n", err)
	}
}
