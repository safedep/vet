package clawhub

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"github.com/safedep/vet/pkg/common/logger"
)

const maxFileReadSize = 200 * 1024 // 200KB

// skillCacheEntry holds a temp file containing the raw zip archive and a
// pre-built index of valid file entries. The zip.File entries read from
// the temp file on demand via the io.ReaderAt interface, avoiding holding
// the entire zip contents in memory.
type skillCacheEntry struct {
	zipFile   *os.File             // temp file backing the zip.Reader
	fileIndex map[string]*zip.File // clean path → zip.File (directories excluded)
}

// fileListEntry describes a single file in a skill package.
type fileListEntry struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// listFiles returns all files in the cached zip as fileListEntry values.
func (e *skillCacheEntry) listFiles() []fileListEntry {
	files := make([]fileListEntry, 0, len(e.fileIndex))
	for p, f := range e.fileIndex {
		files = append(files, fileListEntry{
			Path: p,
			Size: int64(f.UncompressedSize64),
		})
	}
	return files
}

// readFile reads the contents of a single file from the zip backed by
// the temp file on disk.
func (e *skillCacheEntry) readFile(filePath string) ([]byte, error) {
	clean := path.Clean(filePath)
	f, ok := e.fileIndex[clean]
	if !ok {
		return nil, fmt.Errorf("file not found: %s", filePath)
	}

	if f.UncompressedSize64 > maxFileReadSize {
		return nil, fmt.Errorf("file too large (%d bytes, max %d)", f.UncompressedSize64, maxFileReadSize)
	}

	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open zip entry: %w", err)
	}
	defer func() {
		if err := rc.Close(); err != nil {
			logger.Warnf("failed to close zip entry reader: %v", err)
		}
	}()

	data, err := io.ReadAll(io.LimitReader(rc, int64(maxFileReadSize)+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return data, nil
}

// skillCache caches downloaded skill zips as temp-file-backed zip readers.
type skillCache struct {
	mu      sync.Mutex
	client  *Client
	entries map[string]*skillCacheEntry
}

func newSkillCache(client *Client) *skillCache {
	return &skillCache{
		client:  client,
		entries: make(map[string]*skillCacheEntry),
	}
}

// get downloads and indexes the skill zip if not already cached,
// then returns the cached entry.
func (sc *skillCache) get(ctx context.Context, slug string) (*skillCacheEntry, error) {
	slug = normalizeSlug(slug)

	sc.mu.Lock()
	defer sc.mu.Unlock()

	if entry, ok := sc.entries[slug]; ok {
		return entry, nil
	}

	data, err := sc.client.DownloadSkillZip(ctx, slug)
	if err != nil {
		return nil, fmt.Errorf("failed to download skill zip: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "vet-clawhub-*.zip")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	committed := false
	defer func() {
		if !committed {
			closeTempFile(tmpFile)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write zip to temp file: %w", err)
	}

	fileIndex, err := buildFileIndex(tmpFile, int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("failed to index skill zip: %w", err)
	}

	entry := &skillCacheEntry{
		zipFile:   tmpFile,
		fileIndex: fileIndex,
	}

	sc.entries[slug] = entry
	committed = true

	return entry, nil
}

// Cleanup closes and removes all cached temp files.
func (sc *skillCache) Cleanup() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	for _, entry := range sc.entries {
		closeTempFile(entry.zipFile)
	}
	sc.entries = make(map[string]*skillCacheEntry)
}

// closeTempFile closes and removes a temp file, logging warnings on errors.
func closeTempFile(f *os.File) {
	if err := f.Close(); err != nil {
		logger.Warnf("failed to close zip temp file: %v", err)
	}

	if err := os.Remove(f.Name()); err != nil {
		logger.Warnf("failed to remove zip temp file: %v", err)
	}
}

// isValidZipEntry returns true if the zip entry name is safe to index.
// It rejects absolute paths, path traversal components, and symlinks.
func isValidZipEntry(name string, mode fs.FileMode) bool {
	if strings.HasPrefix(name, "/") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return false
		}
	}
	return mode&fs.ModeSymlink == 0
}

// buildFileIndex creates a zip.Reader from the given io.ReaderAt and builds
// a map of clean file paths to their zip.File entries, skipping directories
// and invalid entries.
func buildFileIndex(r io.ReaderAt, size int64) (map[string]*zip.File, error) {
	reader, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("failed to open zip: %w", err)
	}

	index := make(map[string]*zip.File, len(reader.File))
	for _, f := range reader.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if !isValidZipEntry(f.Name, f.Mode()) {
			continue
		}
		clean := path.Clean(f.Name)
		index[clean] = f
	}

	return index, nil
}

// NewSkillTools creates the set of ClawHub skill tools for use with the agent.
// The returned cleanup function closes and removes all cached temp files and
// must be called when the tools are no longer needed.
func NewSkillTools(client *Client) (tools []tool.BaseTool, cleanup func()) {
	cache := newSkillCache(client)
	tools = []tool.BaseTool{
		&getSkillInfoTool{client: client},
		&listSkillFilesTool{cache: cache},
		&readSkillFileTool{cache: cache},
	}
	return tools, cache.Cleanup
}

// --- clawhub_get_skill_info ---

type getSkillInfoTool struct {
	client *Client
}

type getSkillInfoParams struct {
	Slug string `json:"slug"`
}

func (t *getSkillInfoTool) Info(_ context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{
		Name: "clawhub_get_skill_info",
		Desc: "Fetch metadata about a ClawHub skill including name, summary, tags, stats, owner, and latest version info.",
		ParamsOneOf: schema.NewParamsOneOfByParams(map[string]*schema.ParameterInfo{
			"slug": {Type: schema.String, Desc: "The ClawHub skill slug to look up", Required: true},
		}),
	}, nil
}

func (t *getSkillInfoTool) InvokableRun(ctx context.Context, argumentsInJSON string, _ ...tool.Option) (string, error) {
	var params getSkillInfoParams
	if err := json.Unmarshal([]byte(argumentsInJSON), &params); err != nil {
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}

	if params.Slug == "" {
		return "", fmt.Errorf("slug is required")
	}

	resp, err := t.client.GetSkill(ctx, params.Slug)
	if err != nil {
		return "", err
	}

	out, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal response: %w", err)
	}

	return string(out), nil
}

// --- clawhub_list_skill_files ---

type listSkillFilesTool struct {
	cache *skillCache
}

type listSkillFilesParams struct {
	Slug string `json:"slug"`
}

func (t *listSkillFilesTool) Info(_ context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{
		Name: "clawhub_list_skill_files",
		Desc: "List all files in a ClawHub skill package. Downloads the skill zip on first call.",
		ParamsOneOf: schema.NewParamsOneOfByParams(map[string]*schema.ParameterInfo{
			"slug": {Type: schema.String, Desc: "The ClawHub skill slug", Required: true},
		}),
	}, nil
}

func (t *listSkillFilesTool) InvokableRun(ctx context.Context, argumentsInJSON string, _ ...tool.Option) (string, error) {
	var params listSkillFilesParams
	if err := json.Unmarshal([]byte(argumentsInJSON), &params); err != nil {
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}

	if params.Slug == "" {
		return "", fmt.Errorf("slug is required")
	}

	entry, err := t.cache.get(ctx, params.Slug)
	if err != nil {
		return "", err
	}

	files := entry.listFiles()

	out, err := json.MarshalIndent(files, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal file list: %w", err)
	}

	return string(out), nil
}

// --- clawhub_read_skill_file ---

type readSkillFileTool struct {
	cache *skillCache
}

type readSkillFileParams struct {
	Slug string `json:"slug"`
	Path string `json:"path"`
}

func (t *readSkillFileTool) Info(_ context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{
		Name: "clawhub_read_skill_file",
		Desc: "Read the contents of a file from a ClawHub skill package. Returns the raw file content as a string.",
		ParamsOneOf: schema.NewParamsOneOfByParams(map[string]*schema.ParameterInfo{
			"slug": {Type: schema.String, Desc: "The ClawHub skill slug", Required: true},
			"path": {Type: schema.String, Desc: "The relative file path within the skill package", Required: true},
		}),
	}, nil
}

func (t *readSkillFileTool) InvokableRun(ctx context.Context, argumentsInJSON string, _ ...tool.Option) (string, error) {
	var params readSkillFileParams
	if err := json.Unmarshal([]byte(argumentsInJSON), &params); err != nil {
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}

	if params.Slug == "" {
		return "", fmt.Errorf("slug is required")
	}

	if params.Path == "" {
		return "", fmt.Errorf("path is required")
	}

	entry, err := t.cache.get(ctx, params.Slug)
	if err != nil {
		return "", err
	}

	data, err := entry.readFile(params.Path)
	if err != nil {
		return "", err
	}

	return string(data), nil
}
