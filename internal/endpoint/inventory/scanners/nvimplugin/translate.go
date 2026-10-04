package nvimplugin

import (
	"strconv"

	"github.com/safedep/vet/v2/internal/endpoint/inventory"
)

const (
	// appName distinguishes Neovim plugins from VSIX extensions, which
	// reuse the same wire Kind. appDisplay is its human-facing form.
	appName    = "neovim"
	appDisplay = "Neovim"
	pluginHost = "neovim"
)

// Metadata keys carried on each plugin item; the local sink duplicates the
// subset it renders.
const (
	metaKeyAppDisplay    = "app.display"
	metaKeyPluginHost    = "plugin.host"
	metaKeyPluginManager = "plugin.manager"
	metaKeyEcosystem     = "plugin.ecosystem"
	metaKeyRepository    = "plugin.repository"
	metaKeyPurl          = "plugin.purl"
	metaKeyCommit        = "plugin.commit"
	metaKeyLockedCommit  = "plugin.locked_commit"
	metaKeyLockedBranch  = "plugin.locked_branch"
	metaKeyInstallPath   = "plugin.install_path"
	metaKeyDeclared      = "plugin.declared"
	metaKeyInstalled     = "plugin.installed"
)

// translate converts a discovered Plugin into an inventory.Item. Pure and
// deterministic.
func translate(manager string, p Plugin) *inventory.Item {
	// Display name prefers owner/repo; the identity keys off the stable
	// manager-local name (install-dir base / lock key) so it does not change
	// when a lock-only plugin later installs and gains owner/repo.
	displayName := p.Name
	if p.Owner != "" && p.Repo != "" {
		displayName = p.Owner + "/" + p.Repo
	}

	meta := map[string]string{
		metaKeyAppDisplay:    appDisplay,
		metaKeyPluginHost:    pluginHost,
		metaKeyPluginManager: manager,
		metaKeyInstallPath:   p.InstallDir,
		metaKeyDeclared:      strconv.FormatBool(p.Declared),
		metaKeyInstalled:     strconv.FormatBool(p.Installed),
	}
	// Empty values are omitted rather than written as empty strings.
	setIfNotEmpty(meta, metaKeyEcosystem, p.Ecosystem)
	setIfNotEmpty(meta, metaKeyRepository, p.Repository)
	setIfNotEmpty(meta, metaKeyPurl, buildPurl(repoInfo{Ecosystem: p.Ecosystem, Owner: p.Owner, Repo: p.Repo}, p.Commit))
	setIfNotEmpty(meta, metaKeyCommit, p.Commit)
	setIfNotEmpty(meta, metaKeyLockedCommit, p.LockCommit)
	setIfNotEmpty(meta, metaKeyLockedBranch, p.LockBranch)

	return &inventory.Item{
		Kind:         inventory.KindIDEExtension,
		ItemIdentity: inventory.ItemIdentity(appName, inventory.KindIDEExtension, inventory.ScopeSystem, p.Name, p.InstallDir),
		SourceID:     inventory.SourceID(appName, p.SourcePath),
		Name:         displayName,
		App:          appName,
		Scope:        inventory.ScopeSystem,
		ConfigPath:   p.InstallDir,
		Metadata:     meta,
	}
}

func setIfNotEmpty(m map[string]string, k, v string) {
	if v != "" {
		m[k] = v
	}
}
