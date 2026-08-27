// Package config loads and exposes assessment configuration. Configuration
// comes from a YAML file, the QYVORA_SHAKA_* environment namespace, and
// safe defaults, in that order of precedence. Invalid configured values are
// rejected rather than silently accepted.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const appName = "qyvora-shaka"

// Default timeout for directory operations when none is configured.
const DefaultTimeout = 15 * time.Second

// Profile names. Shaka's profiles select how deep an assessment goes; each is
// a clearly defined scope, never "do less because we got bored".
const (
	ProfileQuick          = "quick"
	ProfileStandard       = "standard"
	ProfileDeep           = "deep"
	ProfileDirectory      = "directory"
	ProfileAuthentication = "authentication"
	ProfileTrust          = "trust"
	ProfileIdentity       = "identity"
	ProfileCompliance     = "compliance"
	ProfileResearch       = "research"
)

// Profiles lists every supported profile in documentation order.
var Profiles = []string{
	ProfileQuick, ProfileStandard, ProfileDeep, ProfileDirectory,
	ProfileAuthentication, ProfileTrust, ProfileIdentity,
	ProfileCompliance, ProfileResearch,
}

// IsValidProfile reports whether name is a known profile.
func IsValidProfile(name string) bool {
	for _, p := range Profiles {
		if p == name {
			return true
		}
	}
	return false
}

// Load builds a viper configuration from a config file (when given), the
// QYVORA_SHAKA_* environment namespace, and defaults. A missing config file
// is not an error; a malformed one is.
func Load(cfgFile string) (*viper.Viper, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")

	for _, dir := range configSearchDirs(cfgFile) {
		v.AddConfigPath(dir)
	}

	v.SetEnvPrefix("QYVORA_SHAKA")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	v.SetDefault("profile", ProfileStandard)
	v.SetDefault("output", "terminal")
	v.SetDefault("verbose", false)
	v.SetDefault("quiet", false)
	v.SetDefault("json", false)
	v.SetDefault("authorized", false)
	v.SetDefault("report.dir", "reports")
	v.SetDefault("report.format", "terminal")
	v.SetDefault("log.level", "info")
	v.SetDefault("ldap.port", 389)
	v.SetDefault("ldap.timeout_seconds", 15)
	v.SetDefault("ldap.page_size", 500)
	v.SetDefault("depth.max", 6)
	v.SetDefault("workers", 8)
	v.SetDefault("concurrency.discovery", 8)
	v.SetDefault("concurrency.followup", 8)
	v.SetDefault("session.dir", "")
	v.SetDefault("profile.query", "default")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}
	return v, nil
}

// Profile returns the configured profile name, validated against the known
// set. An invalid configured profile is an error so a typo cannot silently
// change what an assessment does.
func Profile(v *viper.Viper) (string, error) {
	p := v.GetString("profile")
	if !IsValidProfile(p) {
		return "", fmt.Errorf("unknown profile %q (valid: %s)", p, strings.Join(Profiles, ", "))
	}
	return p, nil
}

// HumanTimeout returns the configured LDAP timeout.
func HumanTimeout(v *viper.Viper) time.Duration {
	secs := v.GetInt("ldap.timeout_seconds")
	if secs <= 0 {
		return DefaultTimeout
	}
	return time.Duration(secs) * time.Second
}

func configSearchDirs(cfgFile string) []string {
	dirs := []string{"."}

	if cfgFile != "" {
		if info, err := os.Stat(cfgFile); err == nil && info.IsDir() {
			dirs = append(dirs, cfgFile)
		} else {
			dirs = append(dirs, filepath.Dir(cfgFile))
		}
	}

	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "."+appName))
		dirs = append(dirs, filepath.Join(home, ".config", "qyvora", "shaka"))
	}

	dirs = append(dirs, filepath.Join("/etc", appName))
	return dirs
}
