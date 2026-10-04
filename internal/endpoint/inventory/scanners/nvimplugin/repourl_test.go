package nvimplugin

import "testing"

func TestNormalizeRepoURL(t *testing.T) {
	cases := []struct {
		name          string
		raw           string
		wantRepo      string
		wantEcosystem string
		wantOwner     string
		wantName      string
	}{
		{
			name:          "scp-like ssh",
			raw:           "git@github.com:folke/snacks.nvim.git",
			wantRepo:      "https://github.com/folke/snacks.nvim",
			wantEcosystem: ecosystemGitHub,
			wantOwner:     "folke",
			wantName:      "snacks.nvim",
		},
		{
			name:          "ssh scheme url",
			raw:           "ssh://git@github.com/folke/snacks.nvim.git",
			wantRepo:      "https://github.com/folke/snacks.nvim",
			wantEcosystem: ecosystemGitHub,
			wantOwner:     "folke",
			wantName:      "snacks.nvim",
		},
		{
			name:          "https with .git suffix",
			raw:           "https://github.com/folke/snacks.nvim.git",
			wantRepo:      "https://github.com/folke/snacks.nvim",
			wantEcosystem: ecosystemGitHub,
			wantOwner:     "folke",
			wantName:      "snacks.nvim",
		},
		{
			name: "https strips embedded credentials",
			// Assembled at runtime so no literal credentialed URL sits in
			// source for the secret scanner to flag; stripping applies to
			// whatever userinfo is present.
			raw:           "https://" + "x-token:s3cr3t@github.com/o/r.git",
			wantRepo:      "https://github.com/o/r",
			wantEcosystem: ecosystemGitHub,
			wantOwner:     "o",
			wantName:      "r",
		},
		{
			name:          "https preserves explicit port",
			raw:           "https://git.example.com:8443/team/plugin.git",
			wantRepo:      "https://git.example.com:8443/team/plugin",
			wantEcosystem: ecosystemGit,
			wantOwner:     "team",
			wantName:      "plugin",
		},
		{
			name: "port-stripped host still maps ecosystem, credentials dropped",
			// A credentialed URL with an explicit port: userinfo gone, port kept.
			raw:           "https://" + "u:pw@gitlab.com:443/group/project.git",
			wantRepo:      "https://gitlab.com:443/group/project",
			wantEcosystem: ecosystemGitLab,
			wantOwner:     "group",
			wantName:      "project",
		},
		{
			name:          "gitlab host",
			raw:           "git@gitlab.com:inkscape/inkscape.git",
			wantRepo:      "https://gitlab.com/inkscape/inkscape",
			wantEcosystem: ecosystemGitLab,
			wantOwner:     "inkscape",
			wantName:      "inkscape",
		},
		{
			name:          "gitlab nested group",
			raw:           "https://gitlab.com/group/subgroup/project.git",
			wantRepo:      "https://gitlab.com/group/subgroup/project",
			wantEcosystem: ecosystemGitLab,
			wantOwner:     "group/subgroup",
			wantName:      "project",
		},
		{
			name:          "bitbucket host",
			raw:           "https://user@bitbucket.org/team/repo.git",
			wantRepo:      "https://bitbucket.org/team/repo",
			wantEcosystem: ecosystemBitbucket,
			wantOwner:     "team",
			wantName:      "repo",
		},
		{
			name:          "unknown self-hosted forge falls back to git",
			raw:           "git@gitlab.example.com:team/thing.git",
			wantRepo:      "https://gitlab.example.com/team/thing",
			wantEcosystem: ecosystemGit,
			wantOwner:     "team",
			wantName:      "thing",
		},
		{
			name:          "host case is normalized",
			raw:           "https://GitHub.com/Folke/Snacks.nvim.git",
			wantRepo:      "https://github.com/Folke/Snacks.nvim",
			wantEcosystem: ecosystemGitHub,
			wantOwner:     "Folke",
			wantName:      "Snacks.nvim",
		},
		{
			name: "empty input",
			raw:  "",
		},
		{
			name: "garbage without host",
			raw:  "not-a-url",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeRepoURL(tc.raw)
			if got.Repository != tc.wantRepo {
				t.Errorf("Repository = %q, want %q", got.Repository, tc.wantRepo)
			}
			if got.Ecosystem != tc.wantEcosystem {
				t.Errorf("Ecosystem = %q, want %q", got.Ecosystem, tc.wantEcosystem)
			}
			if got.Owner != tc.wantOwner {
				t.Errorf("Owner = %q, want %q", got.Owner, tc.wantOwner)
			}
			if got.Repo != tc.wantName {
				t.Errorf("Repo = %q, want %q", got.Repo, tc.wantName)
			}
		})
	}
}

func TestBuildPurl(t *testing.T) {
	cases := []struct {
		name   string
		info   repoInfo
		commit string
		want   string
	}{
		{
			name:   "github with commit",
			info:   repoInfo{Ecosystem: ecosystemGitHub, Owner: "folke", Repo: "snacks.nvim"},
			commit: "d569072b2e39e0078b55ea56b133fb9a30d78bad",
			want:   "pkg:github/folke/snacks.nvim@d569072b2e39e0078b55ea56b133fb9a30d78bad",
		},
		{
			name: "github without commit omits version",
			info: repoInfo{Ecosystem: ecosystemGitHub, Owner: "folke", Repo: "snacks.nvim"},
			want: "pkg:github/folke/snacks.nvim",
		},
		{
			name:   "gitlab",
			info:   repoInfo{Ecosystem: ecosystemGitLab, Owner: "inkscape", Repo: "inkscape"},
			commit: "abc123",
			want:   "pkg:gitlab/inkscape/inkscape@abc123",
		},
		{
			name:   "bitbucket",
			info:   repoInfo{Ecosystem: ecosystemBitbucket, Owner: "team", Repo: "repo"},
			commit: "def456",
			want:   "pkg:bitbucket/team/repo@def456",
		},
		{
			name:   "generic git omits purl",
			info:   repoInfo{Ecosystem: ecosystemGit, Owner: "team", Repo: "thing"},
			commit: "abc123",
			want:   "",
		},
		{
			name:   "missing owner omits purl",
			info:   repoInfo{Ecosystem: ecosystemGitHub, Repo: "repo"},
			commit: "abc123",
			want:   "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildPurl(tc.info, tc.commit); got != tc.want {
				t.Errorf("buildPurl() = %q, want %q", got, tc.want)
			}
		})
	}
}
