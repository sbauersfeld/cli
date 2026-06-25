package databrickscfg

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/databricks/cli/libs/log"
	"github.com/databricks/databricks-sdk-go/config"
	"gopkg.in/ini.v1"
)

var ResolveProfileFromHost = profileFromHostLoader{}

// ResolveNonAuthFromEnv reads configuration from environment variables, except
// for the host and any authentication credential. It runs before the config
// file loader when the user has explicitly selected a profile (via the
// --profile flag or workspace.profile), so that the profile takes precedence
// over auth environment variables.
//
// The SDK's default loader order is environment first, then config file, and a
// loader never overwrites a field that is already set. As a result auth env
// vars (DATABRICKS_HOST, DATABRICKS_TOKEN, ...) shadow the selected profile.
// Skipping them here lets the subsequent config-file loader populate host and
// auth from the profile instead. A trailing config.ConfigAttributes loader can
// still fill auth fields the profile leaves empty (e.g. a host-only profile
// combined with DATABRICKS_TOKEN). See
// https://github.com/databricks/cli/issues/5096.
var ResolveNonAuthFromEnv = nonAuthEnvLoader{}

// ProfileAuthLoaders is the SDK loader chain to use when the user has
// explicitly selected a profile (via the --profile flag or a bundle's
// workspace.profile). It is the single source of truth for that precedence
// rule; call sites should reference it rather than restating the rationale.
//
// The selected profile must determine the host, routing identifiers, and
// authentication, taking precedence over the matching environment variables
// (DATABRICKS_HOST, DATABRICKS_TOKEN, ...). The SDK's default chain reads the
// environment before the config file and never overwrites an already-set
// field, so the env vars would otherwise shadow the profile (issue #5096).
//
// Note: this intentionally only governs an explicitly selected profile. A
// profile picked up from DATABRICKS_CONFIG_PROFILE keeps the SDK's default
// env-first precedence; see the call sites in cmd/root for the rationale.
//
// The order matters:
//  1. ResolveNonAuthFromEnv loads non-auth, non-routing attributes from the
//     environment (e.g. cluster_id), preserving env-wins precedence for those.
//  2. ConfigFile loads the selected profile, populating host, routing and auth.
//  3. ConfigAttributes loads any remaining attributes from the environment,
//     filling fields the profile did not provide (e.g. a host-only profile
//     combined with DATABRICKS_TOKEN). It never overwrites a value the profile
//     already set, so the profile still wins for #5096. This gap-fill is a
//     deliberate, tested contract (host-only profiles are a common CI pattern
//     where the credential is injected via the environment).
var ProfileAuthLoaders = []config.Loader{
	ResolveNonAuthFromEnv,
	config.ConfigFile,
	config.ConfigAttributes,
}

var errNoMatchingProfiles = errors.New("no matching config profiles found")

type errMultipleProfiles []string

func (e errMultipleProfiles) Error() string {
	return "multiple profiles matched: " + strings.Join(e, ", ")
}

// AsMultipleProfiles checks if the error is caused by multiple profiles
// matching the same host. If so, it returns the matching profile names.
func AsMultipleProfiles(err error) ([]string, bool) {
	if e, ok := errors.AsType[errMultipleProfiles](err); ok {
		return []string(e), true
	}
	return nil, false
}

func findMatchingProfile(configFile *config.File, matcher func(*ini.Section) bool) (*ini.Section, error) {
	// Look for sections in the configuration file that match the configured host.
	var matching []*ini.Section
	for _, section := range configFile.Sections() {
		if !matcher(section) {
			continue
		}
		matching = append(matching, section)
	}

	// If there are no matching sections, we don't do anything.
	if len(matching) == 0 {
		return nil, errNoMatchingProfiles
	}

	// If there are multiple matching sections, let the user know it is impossible
	// to unambiguously select a profile to use.
	if len(matching) > 1 {
		var names errMultipleProfiles
		for _, section := range matching {
			names = append(names, section.Name())
		}

		return nil, names
	}

	return matching[0], nil
}

// nonAuthEnvSkipAttrs lists SDK config attribute names that nonAuthEnvLoader
// must not read from the environment, beyond those caught by HasAuthAttribute.
//
// Criterion: an attribute belongs here if it identifies the target
// workspace/account (host, routing IDs) or selects/steers the authentication
// method, but the SDK does NOT tag it `auth:"..."` (so HasAuthAttribute can't
// catch it). The SDK collapses an `auth:"-"` tag to an empty auth tag (marking
// the field "internal"), which is why these auth-steering fields slip past
// HasAuthAttribute and must be listed explicitly. Leaving any of them to the
// environment would let the matching env var shadow the selected profile, the
// same bug as #5096. Skipping here only changes precedence: the trailing
// ConfigAttributes loader still fills any of these the profile leaves empty
// from the environment (the same gap-fill host and credentials get).
//
//   - host: has no `auth` struct tag at all.
//   - workspace_id (DATABRICKS_WORKSPACE_ID): routing identifier; a profile
//     that sets it must win, or a stray env var routes the profile's
//     credentials to a different workspace.
//   - account_id (DATABRICKS_ACCOUNT_ID): account routing identifier, same
//     reasoning as workspace_id.
//   - auth_type (DATABRICKS_AUTH_TYPE): forces a specific auth method.
//   - discovery_url (DATABRICKS_DISCOVERY_URL): redirects OIDC discovery.
//   - audience (DATABRICKS_TOKEN_AUDIENCE): selects the token audience for
//     OIDC/workload-identity flows.
//   - cloud (DATABRICKS_CLOUD): steers cloud-specific auth (Azure/GCP/AWS).
//
// Non-auth env-backed attributes tagged `auth:"-"` (e.g. oauth_callback_port,
// debug_headers, rate_limit) are intentionally NOT skipped: they don't change
// which credentials authenticate the request or where it is routed, so
// env-wins precedence is fine. TestNonAuthEnvSkipAttrsCoverSDKInternalEnvAttrs
// guards that every auth-steering internal attribute stays classified across
// SDK bumps.
var nonAuthEnvSkipAttrs = map[string]bool{
	"host":          true,
	"workspace_id":  true,
	"account_id":    true,
	"auth_type":     true,
	"discovery_url": true,
	"audience":      true,
	"cloud":         true,
}

type nonAuthEnvLoader struct{}

func (nonAuthEnvLoader) Name() string {
	return "environment (excluding auth)"
}

func (nonAuthEnvLoader) Configure(cfg *config.Config) error {
	for _, attr := range config.ConfigAttributes {
		// Leave the host and authentication settings for the config file
		// (i.e. the selected profile) to provide.
		if nonAuthEnvSkipAttrs[attr.Name] || attr.HasAuthAttribute() {
			continue
		}
		// Match the SDK loader semantics: don't overwrite a value previously set.
		if !attr.IsZero(cfg) {
			continue
		}
		v, envName := attr.ReadEnv()
		if v == "" {
			continue
		}
		if err := attr.SetS(cfg, v); err != nil {
			return err
		}
		// Record the source so `databricks auth describe` and debug output
		// attribute the value to the environment, matching the SDK loader.
		cfg.SetAttrSource(&attr, config.Source{Type: config.SourceEnv, Name: envName})
	}
	return nil
}

type profileFromHostLoader struct{}

func (l profileFromHostLoader) Name() string {
	return "resolve-profile-from-host"
}

func (l profileFromHostLoader) Configure(cfg *config.Config) error {
	// Skip an attempt to resolve a profile from the host if any authentication
	// is already configured (either directly, through environment variables, or
	// if a profile was specified).
	if cfg.Host == "" || l.isAnyAuthConfigured(cfg) {
		return nil
	}

	ctx := context.Background() //nolint:gocritic // SDK interface does not accept context.
	configFile, err := config.LoadFile(cfg.ConfigFile)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("cannot parse config file: %w", err)
	}
	// Normalized version of the configured host.
	host := normalizeHost(cfg.Host)
	match, err := findMatchingProfile(configFile, func(s *ini.Section) bool {
		key, err := s.GetKey("host")
		if err != nil {
			log.Tracef(ctx, "section %s: %s", s.Name(), err)
			return false
		}

		// Check if this section matches the normalized host
		return normalizeHost(key.Value()) == host
	})
	if err == errNoMatchingProfiles {
		return nil
	}

	// If multiple profiles match the same host and we have a workspace_id,
	// try to disambiguate by matching workspace_id.
	if names, ok := AsMultipleProfiles(err); ok && cfg.WorkspaceID != "" {
		originalErr := err
		match, err = l.disambiguateByWorkspaceID(ctx, configFile, host, cfg.WorkspaceID, names)
		if err == errNoMatchingProfiles {
			// workspace_id didn't match any of the host-matching profiles.
			// Fall back to the original ambiguity error.
			log.Debugf(ctx, "workspace_id=%s did not match any profiles for host %s: %v", cfg.WorkspaceID, host, names)
			err = originalErr
		}
	}

	if _, ok := AsMultipleProfiles(err); ok {
		return fmt.Errorf(
			"%s: %w: please set DATABRICKS_CONFIG_PROFILE or provide --profile flag to specify one",
			host, err)
	}
	if err != nil {
		return err
	}

	log.Debugf(ctx, "Loading profile %s because of host match", match.Name())
	err = config.ConfigAttributes.ResolveFromStringMapWithSource(cfg, match.KeysHash(), config.Source{
		Type: config.SourceFile,
		Name: configFile.Path(),
	})
	if err != nil {
		return fmt.Errorf("%s %s profile: %w", configFile.Path(), match.Name(), err)
	}

	cfg.Profile = match.Name()
	return nil
}

// disambiguateByWorkspaceID filters the profiles that matched a host by workspace_id.
func (l profileFromHostLoader) disambiguateByWorkspaceID(
	ctx context.Context,
	configFile *config.File,
	host string,
	workspaceID string,
	profileNames []string,
) (*ini.Section, error) {
	log.Debugf(ctx, "Multiple profiles matched host %s, disambiguating by workspace_id=%s", host, workspaceID)

	nameSet := make(map[string]bool, len(profileNames))
	for _, name := range profileNames {
		nameSet[name] = true
	}

	return findMatchingProfile(configFile, func(s *ini.Section) bool {
		if !nameSet[s.Name()] {
			return false
		}
		key, err := s.GetKey("workspace_id")
		if err != nil {
			return false
		}
		return key.Value() == workspaceID
	})
}

func (l profileFromHostLoader) isAnyAuthConfigured(cfg *config.Config) bool {
	// If any of the auth-specific attributes are set, we can skip profile resolution.
	for _, a := range config.ConfigAttributes {
		if !a.HasAuthAttribute() {
			continue
		}
		if !a.IsZero(cfg) {
			return true
		}
	}
	// If the auth type is set, we can skip profile resolution.
	// For example, to force "azure-cli", only the host and the auth type will be set.
	return cfg.AuthType != ""
}
