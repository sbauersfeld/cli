package databrickscfg

import (
	"errors"
	"testing"

	"github.com/databricks/databricks-sdk-go/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoaderSkipsEmptyHost(t *testing.T) {
	cfg := config.Config{
		Loaders: []config.Loader{
			ResolveProfileFromHost,
		},
		Host: "",
	}

	err := cfg.EnsureResolved()
	assert.NoError(t, err)
}

func TestLoaderSkipsExistingAuth(t *testing.T) {
	cfg := config.Config{
		Loaders: []config.Loader{
			ResolveProfileFromHost,
		},
		Host:  "https://foo.test",
		Token: "nonempty means pat auth",
	}

	err := cfg.EnsureResolved()
	assert.NoError(t, err)
}

func TestResolveNonAuthFromEnvSkipsHostAndAuth(t *testing.T) {
	t.Setenv("DATABRICKS_HOST", "https://env.test")
	t.Setenv("DATABRICKS_TOKEN", "env-token")
	// auth_type, discovery_url, audience and cloud are tagged auth:"-" in the
	// SDK, so HasAuthAttribute can't catch them; they steer authentication and
	// must still be skipped (#5096).
	t.Setenv("DATABRICKS_AUTH_TYPE", "oauth-m2m")
	t.Setenv("DATABRICKS_DISCOVERY_URL", "https://discovery.env.test")
	t.Setenv("DATABRICKS_TOKEN_AUDIENCE", "env-audience")
	t.Setenv("DATABRICKS_CLOUD", "azure")
	// workspace_id and account_id are routing identifiers; a profile that sets
	// them must win, so they are skipped too (#5096).
	t.Setenv("DATABRICKS_WORKSPACE_ID", "env-workspace")
	t.Setenv("DATABRICKS_ACCOUNT_ID", "env-account")
	t.Setenv("DATABRICKS_CLUSTER_ID", "env-cluster")

	cfg := &config.Config{}
	err := ResolveNonAuthFromEnv.Configure(cfg)
	require.NoError(t, err)

	// Host, routing and auth settings are left for the profile (config file) to set.
	assert.Empty(t, cfg.Host)
	assert.Empty(t, cfg.Token)
	assert.Empty(t, cfg.AuthType)
	assert.Empty(t, cfg.DiscoveryURL)
	assert.Empty(t, cfg.TokenAudience)
	assert.Empty(t, cfg.Cloud)
	assert.Empty(t, cfg.WorkspaceID)
	assert.Empty(t, cfg.AccountID)
	// Non-auth attributes are still populated from the environment.
	assert.Equal(t, "env-cluster", cfg.ClusterID)
}

// TestNonAuthEnvSkipAttrsCoverSDKInternalEnvAttrs guards against an SDK bump
// silently re-introducing #5096. nonAuthEnvSkipAttrs and HasAuthAttribute
// together must classify every env-backed attribute that steers authentication.
// The dangerous category is attributes the SDK tags `auth:"-"` (Internal, so
// HasAuthAttribute returns false) yet read from the environment: if the SDK
// adds a new auth-steering one, it would shadow the selected profile again.
//
// Every Internal env-backed attribute must therefore be either skipped
// (auth-steering) or listed below as a reviewed env-first attribute (it does
// not change which credentials authenticate or where the request is routed).
// A new SDK attribute fails this test until a human classifies it.
func TestNonAuthEnvSkipAttrsCoverSDKInternalEnvAttrs(t *testing.T) {
	knownEnvFirstInternal := map[string]bool{
		"oauth_callback_port":         true,
		"disable_oauth_refresh_token": true,
		"debug_truncate_bytes":        true,
		"debug_headers":               true,
		"rate_limit":                  true,
	}

	for _, attr := range config.ConfigAttributes {
		if !attr.Internal || len(attr.EnvVars) == 0 {
			continue
		}
		if nonAuthEnvSkipAttrs[attr.Name] || knownEnvFirstInternal[attr.Name] {
			continue
		}
		t.Errorf("SDK config attribute %q (env %v) is internal (auth:\"-\") but unclassified: "+
			"add it to nonAuthEnvSkipAttrs if it steers auth/routing, or to "+
			"knownEnvFirstInternal if env-first precedence is safe (#5096)",
			attr.Name, attr.EnvVars)
	}
}

func TestLoaderSkipsExplicitAuthType(t *testing.T) {
	cfg := config.Config{
		Loaders: []config.Loader{
			ResolveProfileFromHost,
		},
		ConfigFile: "testdata/databrickscfg",
		Host:       "https://default.test",
		AuthType:   "azure-cli",
	}

	err := cfg.EnsureResolved()
	assert.NoError(t, err)
	assert.Equal(t, "azure-cli", cfg.AuthType)
	assert.Empty(t, cfg.Profile)
	assert.Empty(t, cfg.Token)
}

func TestLoaderSkipsNonExistingConfigFile(t *testing.T) {
	cfg := config.Config{
		Loaders: []config.Loader{
			ResolveProfileFromHost,
		},
		ConfigFile: "idontexist",
		Host:       "https://default.test",
	}

	err := cfg.EnsureResolved()
	assert.NoError(t, err)
	assert.Empty(t, cfg.Token)
}

func TestLoaderErrorsOnInvalidFile(t *testing.T) {
	cfg := config.Config{
		Loaders: []config.Loader{
			ResolveProfileFromHost,
		},
		ConfigFile: "profile/testdata/badcfg",
		Host:       "https://default.test",
	}

	err := cfg.EnsureResolved()
	assert.ErrorContains(t, err, "unclosed section: ")
}

func TestLoaderSkipsNoMatchingHost(t *testing.T) {
	cfg := config.Config{
		Loaders: []config.Loader{
			ResolveProfileFromHost,
		},
		ConfigFile: "profile/testdata/databrickscfg",
		Host:       "https://noneofthehostsmatch.test",
	}

	err := cfg.EnsureResolved()
	assert.NoError(t, err)
	assert.Empty(t, cfg.Token)
}

func TestLoaderMatchingHost(t *testing.T) {
	cfg := config.Config{
		Loaders: []config.Loader{
			ResolveProfileFromHost,
		},
		ConfigFile: "profile/testdata/databrickscfg",
		Host:       "https://default.test",
	}

	err := cfg.EnsureResolved()
	assert.NoError(t, err)
	assert.Equal(t, "default", cfg.Token)
	assert.Equal(t, "DEFAULT", cfg.Profile)
}

func TestLoaderMatchingHostWithQuery(t *testing.T) {
	cfg := config.Config{
		Loaders: []config.Loader{
			ResolveProfileFromHost,
		},
		ConfigFile: "profile/testdata/databrickscfg",
		Host:       "https://query.test/?foo=bar",
	}

	err := cfg.EnsureResolved()
	assert.NoError(t, err)
	assert.Equal(t, "query", cfg.Token)
	assert.Equal(t, "query", cfg.Profile)
}

func TestLoaderErrorsOnMultipleMatches(t *testing.T) {
	cfg := config.Config{
		Loaders: []config.Loader{
			ResolveProfileFromHost,
		},
		ConfigFile: "profile/testdata/databrickscfg",
		Host:       "https://foo.test/bar",
	}

	err := cfg.EnsureResolved()
	assert.Error(t, err)
	assert.ErrorContains(t, err, "https://foo.test: multiple profiles matched: foo1, foo2")
}

func TestAsMultipleProfilesExtractsNames(t *testing.T) {
	cfg := config.Config{
		Loaders: []config.Loader{
			ResolveProfileFromHost,
		},
		ConfigFile: "profile/testdata/databrickscfg",
		Host:       "https://foo.test/bar",
	}

	err := cfg.EnsureResolved()
	require.Error(t, err)

	names, ok := AsMultipleProfiles(err)
	assert.True(t, ok)
	assert.Equal(t, []string{"foo1", "foo2"}, names)
}

func TestAsMultipleProfilesReturnsFalseForUnrelatedError(t *testing.T) {
	names, ok := AsMultipleProfiles(errors.New("some other error"))
	assert.False(t, ok)
	assert.Nil(t, names)
}

func TestAsMultipleProfilesReturnsFalseForNil(t *testing.T) {
	names, ok := AsMultipleProfiles(nil)
	assert.False(t, ok)
	assert.Nil(t, names)
}

func TestLoaderDisambiguatesByWorkspaceID(t *testing.T) {
	cfg := config.Config{
		Loaders: []config.Loader{
			ResolveProfileFromHost,
		},
		ConfigFile:  "profile/testdata/databrickscfg",
		Host:        "https://spog.databricks.com",
		WorkspaceID: "111",
	}

	err := cfg.EnsureResolved()
	require.NoError(t, err)
	assert.Equal(t, "spog-ws1", cfg.Profile)
	assert.Equal(t, "spog-ws1", cfg.Token)
}

func TestLoaderDisambiguatesByWorkspaceIDSecondProfile(t *testing.T) {
	cfg := config.Config{
		Loaders: []config.Loader{
			ResolveProfileFromHost,
		},
		ConfigFile:  "profile/testdata/databrickscfg",
		Host:        "https://spog.databricks.com",
		WorkspaceID: "222",
	}

	err := cfg.EnsureResolved()
	require.NoError(t, err)
	assert.Equal(t, "spog-ws2", cfg.Profile)
	assert.Equal(t, "spog-ws2", cfg.Token)
}

func TestLoaderErrorsOnMultipleMatchesWithSameWorkspaceID(t *testing.T) {
	cfg := config.Config{
		Loaders: []config.Loader{
			ResolveProfileFromHost,
		},
		ConfigFile:  "profile/testdata/databrickscfg",
		Host:        "https://spog-dup.databricks.com",
		WorkspaceID: "333",
	}

	err := cfg.EnsureResolved()
	require.Error(t, err)
	assert.ErrorContains(t, err, "multiple profiles matched: spog-dup1, spog-dup2")
}

func TestLoaderErrorsOnMultipleMatchesWithoutWorkspaceID(t *testing.T) {
	// Without workspace_id, multiple host matches still error as before.
	cfg := config.Config{
		Loaders: []config.Loader{
			ResolveProfileFromHost,
		},
		ConfigFile: "profile/testdata/databrickscfg",
		Host:       "https://spog.databricks.com",
	}

	err := cfg.EnsureResolved()
	require.Error(t, err)
	assert.ErrorContains(t, err, "multiple profiles matched: spog-ws1, spog-ws2")
}

func TestLoaderNoWorkspaceIDMatchFallsThrough(t *testing.T) {
	// workspace_id doesn't match any of the host-matching profiles.
	// Falls back to the original host ambiguity error.
	cfg := config.Config{
		Loaders: []config.Loader{
			ResolveProfileFromHost,
		},
		ConfigFile:  "profile/testdata/databrickscfg",
		Host:        "https://spog.databricks.com",
		WorkspaceID: "999",
	}

	err := cfg.EnsureResolved()
	require.Error(t, err)
	assert.ErrorContains(t, err, "multiple profiles matched: spog-ws1, spog-ws2")
}
