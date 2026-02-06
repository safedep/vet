package clawhub

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

const maxFileReadSize = 200 * 1024 // 200KB

// skillCache caches downloaded and extracted skill zip archives.
type skillCache struct {
	mu      sync.Mutex
	client  *Client
	entries map[string]string // slug -> temp dir path
}

func newSkillCache(client *Client) *skillCache {
	return &skillCache{
		client:  client,
		entries: make(map[string]string),
	}
}

// getExtractDir downloads and extracts the skill zip if not already cached,
// then returns the path to the extraction directory.
func (sc *skillCache) getExtractDir(ctx context.Context, slug string) (string, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if dir, ok := sc.entries[slug]; ok {
		return dir, nil
	}

	data, err := sc.client.DownloadSkillZip(ctx, slug)
	if err != nil {
		return "", fmt.Errorf("failed to download skill zip: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "vet-clawhub-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	if err := extractZip(data, tmpDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to extract skill zip: %w", err)
	}

	sc.entries[slug] = tmpDir
	return tmpDir, nil
}

// Cleanup removes all cached extraction directories.
func (sc *skillCache) Cleanup() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	for _, dir := range sc.entries {
		_ = os.RemoveAll(dir)
	}

	sc.entries = make(map[string]string)
}

func extractZip(data []byte, destDir string) error {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}

	for _, f := range reader.File {
		// Protect against zip slip
		targetPath := filepath.Join(destDir, f.Name) //nolint:gosec
		if !strings.HasPrefix(filepath.Clean(targetPath), filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("invalid zip entry path: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0o750); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0o750); err != nil {
			return fmt.Errorf("failed to create parent directory: %w", err)
		}

		outFile, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return fmt.Errorf("failed to create file: %w", err)
		}

		rc, err := f.Open()
		if err != nil {
			_ = outFile.Close()
			return fmt.Errorf("failed to open zip entry: %w", err)
		}

		_, err = io.Copy(outFile, rc) //nolint:gosec
		_ = rc.Close()
		closeErr := outFile.Close()

		if err != nil {
			return fmt.Errorf("failed to extract file: %w", err)
		}

		if closeErr != nil {
			return fmt.Errorf("failed to close extracted file: %w", closeErr)
		}
	}

	return nil
}

// NewSkillTools creates the set of ClawHub skill tools for use with the agent.
// The returned cleanup function removes all cached temporary directories and
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

type fileListEntry struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

func (t *listSkillFilesTool) Info(_ context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{
		Name: "clawhub_list_skill_files",
		Desc: "List all files in a ClawHub skill package. Downloads and extracts the skill zip on first call.",
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

	dir, err := t.cache.getExtractDir(ctx, params.Slug)
	if err != nil {
		return "", err
	}

	var files []fileListEntry
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}

		files = append(files, fileListEntry{
			Path: relPath,
			Size: info.Size(),
		})
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to walk extracted directory: %w", err)
	}

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

	dir, err := t.cache.getExtractDir(ctx, params.Slug)
	if err != nil {
		return "", err
	}

	targetPath := filepath.Join(dir, params.Path)

	// Protect against path traversal
	cleanTarget := filepath.Clean(targetPath)
	cleanDir := filepath.Clean(dir)
	if !strings.HasPrefix(cleanTarget, cleanDir+string(os.PathSeparator)) {
		return "", fmt.Errorf("invalid file path: %s", params.Path)
	}

	info, err := os.Stat(targetPath)
	if err != nil {
		return "", fmt.Errorf("file not found: %s", params.Path)
	}

	if info.Size() > maxFileReadSize {
		return "", fmt.Errorf("file too large (%d bytes, max %d)", info.Size(), maxFileReadSize)
	}

	data, err := os.ReadFile(targetPath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	return string(data), nil
}
