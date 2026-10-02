package credentials

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/safedep/dry/keychain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileKeychain(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "dir", "keychain.json")
	k := newFileKeychain(path)

	_, err := k.Get(ctx, "a")
	assert.ErrorIs(t, err, keychain.ErrNotFound)
	assert.ErrorIs(t, k.Delete(ctx, "a"), keychain.ErrNotFound)

	require.NoError(t, k.Set(ctx, "a", &keychain.Secret{Value: "one"}))
	require.NoError(t, k.Set(ctx, "b", &keychain.Secret{Value: "two"}))
	s, err := newFileKeychain(path).Get(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, "one", s.Value)

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}

	require.NoError(t, k.Delete(ctx, "a"))
	_, err = k.Get(ctx, "a")
	assert.ErrorIs(t, err, keychain.ErrNotFound)

	require.NoError(t, os.WriteFile(path, []byte("{"), 0o600))
	_, err = k.Get(ctx, "b")
	assert.ErrorContains(t, err, "keychain file")
}

func TestLoginStatusLogout(t *testing.T) {
	t.Setenv("SAFEDEP_API_KEY", "")
	t.Setenv("SAFEDEP_TENANT_ID", "")
	t.Setenv("SAFEDEP_PROFILE", "")
	file := filepath.Join(t.TempDir(), "keychain.json")

	cases := []struct {
		name    string
		profile string
		source  string
		shared  []string
	}{
		{"default profile", "", "default", []string{"safedep cli", "pmg"}},
		{"named profile", "work", "flag or config", []string{"safedep cli"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := FromConfig(tc.profile, false, file)

			st, err := StatusOf(o)
			require.NoError(t, err)
			assert.Empty(t, st.APIKey)
			assert.Empty(t, st.Tenant)

			profile, err := Login(o, " sk_secret_9876\n", "acme.safedep.io ")
			require.NoError(t, err)

			st, err = StatusOf(o)
			require.NoError(t, err)
			assert.Equal(t, profile, st.Profile)
			assert.Equal(t, tc.source, st.ProfileSource)
			assert.Equal(t, "acme.safedep.io", st.Tenant)
			assert.Equal(t, "keychain", st.APIKey)
			assert.Equal(t, "9876", st.KeyHint)
			assert.Equal(t, tc.shared, st.SharedWith)

			_, err = Logout(o)
			require.NoError(t, err)
			st, err = StatusOf(o)
			require.NoError(t, err)
			assert.Empty(t, st.APIKey)
		})
	}
}

func TestLoginKeepsProfilesApart(t *testing.T) {
	t.Setenv("SAFEDEP_API_KEY", "")
	t.Setenv("SAFEDEP_TENANT_ID", "")
	t.Setenv("SAFEDEP_PROFILE", "")
	file := filepath.Join(t.TempDir(), "keychain.json")

	_, err := Login(FromConfig("work", false, file), "sk_work_1111", "work.safedep.io")
	require.NoError(t, err)

	st, err := StatusOf(FromConfig("", false, file))
	require.NoError(t, err)
	assert.Empty(t, st.Tenant)

	t.Setenv("SAFEDEP_PROFILE", "work")
	st, err = StatusOf(FromConfig("", false, file))
	require.NoError(t, err)
	assert.Equal(t, "work.safedep.io", st.Tenant)
	assert.Equal(t, "SAFEDEP_PROFILE", st.ProfileSource)
}
