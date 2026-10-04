package cyclonedx

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

func TestGroupAndName(t *testing.T) {
	cases := []struct {
		eco         model.Ecosystem
		name        string
		group, want string
	}{
		{model.EcosystemNpm, "@babel/core", "@babel", "core"},
		{model.EcosystemNpm, "lodash", "", "lodash"},
		{model.EcosystemMaven, "org.apache:commons", "org.apache", "commons"},
		{model.EcosystemGo, "github.com/spf13/cobra", "github.com/spf13", "cobra"},
		{model.EcosystemVSCode, "ms-python.python", "ms-python", "python"},
		{model.EcosystemOpenVSX, "redhat.vscode-yaml", "redhat", "vscode-yaml"},
		{model.EcosystemPyPI, "Django", "", "Django"},
	}
	for _, tc := range cases {
		t.Run(string(tc.eco)+"/"+tc.name, func(t *testing.T) {
			group, name := groupAndName(model.MustPackageVersion(tc.eco, tc.name, "1.0.0"))
			assert.Equal(t, tc.group, group)
			assert.Equal(t, tc.want, name)
		})
	}
}

func TestVulnerabilityAffectsTheComponent(t *testing.T) {
	id := model.MustPackageVersion(model.EcosystemNpm, "/", "1.0.0")
	require.Empty(t, id.PURL(), "the test needs a name that forms no PURL")
	p := &report.PackageEntry{Package: model.Package{ID: id}}

	c := component(p)
	v := vulnerability(p, model.Vulnerability{ID: "GHSA-1"})
	require.NotEmpty(t, c.BOMRef)
	require.NotNil(t, v.Affects)
	assert.Equal(t, c.BOMRef, (*v.Affects)[0].Ref)
	assert.Equal(t, "GHSA-1/"+c.BOMRef, v.BOMRef)
}
