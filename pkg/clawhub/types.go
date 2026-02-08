package clawhub

// SkillResponse is the response from the ClawHub API for a skill lookup.
type SkillResponse struct {
	Skill         SkillInfo    `json:"skill"`
	LatestVersion *VersionInfo `json:"latestVersion"`
	Owner         *OwnerInfo   `json:"owner"`
}

// SkillInfo contains metadata about a ClawHub skill.
type SkillInfo struct {
	Slug        string            `json:"slug"`
	DisplayName string            `json:"displayName"`
	Summary     string            `json:"summary"`
	Tags        map[string]string `json:"tags"`
	Stats       map[string]any    `json:"stats"`
	CreatedAt   int64             `json:"createdAt"`
	UpdatedAt   int64             `json:"updatedAt"`
}

// VersionInfo contains metadata about a specific skill version.
type VersionInfo struct {
	Version   string `json:"version"`
	Changelog string `json:"changelog"`
	CreatedAt int64  `json:"createdAt"`
}

// OwnerInfo contains metadata about the skill owner.
type OwnerInfo struct {
	Handle      string `json:"handle"`
	DisplayName string `json:"displayName"`
	Image       string `json:"image"`
}

// VersionResponse is the response from the ClawHub API for a skill version lookup.
type VersionResponse struct {
	Skill struct {
		Slug        string `json:"slug"`
		DisplayName string `json:"displayName"`
	} `json:"skill"`
	Version struct {
		Version   string      `json:"version"`
		Changelog string      `json:"changelog"`
		Files     []FileEntry `json:"files"`
	} `json:"version"`
}

// FileEntry represents a file within a skill version.
type FileEntry struct {
	Path        string `json:"path"`
	Size        int    `json:"size"`
	SHA256      string `json:"sha256"`
	ContentType string `json:"contentType"`
}
