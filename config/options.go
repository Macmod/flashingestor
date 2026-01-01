package config

import (
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

// QueryDefinition represents a single LDAP query configuration
type QueryDefinition struct {
	Name       string   `yaml:"name"`
	Filter     string   `yaml:"filter"`
	Attributes []string `yaml:"attributes"`
	PageSize   int      `yaml:"page_size"`
}

// RuntimeOptions holds configurable runtime options that can be changed while running
type RuntimeOptions struct {
	mu sync.RWMutex

	Ingestion struct {
		RecurseTrusts       bool              `yaml:"recurse_trusts"`
		RecurseFeasibleOnly bool              `yaml:"recurse_feasible_only"`
		IncludeACLs         bool              `yaml:"include_acls"`
		SearchForest        bool              `yaml:"search_forest"`
		LdapsToLdapFallback bool              `yaml:"ldaps_to_ldap_fallback"`
		Queries             []QueryDefinition `yaml:"queries"`
	} `yaml:"ingestion"`

	RemoteCollection struct {
		Methods []string `yaml:"methods"`
	} `yaml:"remote_collection"`

	Conversion struct {
		MergeRemote             bool `yaml:"merge_remote"`
		WriterBufsize           int  `yaml:"writer_bufsize"`
		CompressOutput          bool `yaml:"compress_output"`
		CleanupAfterCompression bool `yaml:"cleanup_after_compression"`
	} `yaml:"conversion"`
}

// DefaultOptions returns default runtime options
func DefaultOptions() *RuntimeOptions {
	opts := &RuntimeOptions{}

	// Ingestion defaults
	opts.Ingestion.Queries = GetFallbackQueryDefinitions()
	opts.Ingestion.RecurseTrusts = true
	opts.Ingestion.RecurseFeasibleOnly = true
	opts.Ingestion.IncludeACLs = true
	opts.Ingestion.SearchForest = true
	opts.Ingestion.LdapsToLdapFallback = true

	// Remote collection defaults
	opts.RemoteCollection.Methods = GetFallbackRemoteMethods()

	// Conversion defaults
	convOpts := GetFallbackConversionOpts()
	opts.Conversion.MergeRemote = convOpts.MergeRemote
	opts.Conversion.WriterBufsize = convOpts.WriterBufsize
	opts.Conversion.CompressOutput = convOpts.CompressOutput
	opts.Conversion.CleanupAfterCompression = convOpts.CleanupAfterCompression

	return opts
}

// LoadOptions loads options from a YAML file, or returns defaults if file doesn't exist
func LoadOptions(configPath string) (*RuntimeOptions, error) {
	// If no config path provided, return defaults
	if configPath == "" {
		return DefaultOptions(), nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, return defaults
			return DefaultOptions(), nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	opts := DefaultOptions()
	if err := yaml.Unmarshal(data, opts); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return opts, nil
}

// SaveOptions saves current options to a YAML file
func (opts *RuntimeOptions) SaveOptions(configPath string) error {
	opts.mu.RLock()
	defer opts.mu.RUnlock()

	data, err := yaml.Marshal(opts)
	if err != nil {
		return fmt.Errorf("failed to marshal options: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Thread-safe getters
func (opts *RuntimeOptions) GetRecurseTrusts() bool {
	opts.mu.RLock()
	defer opts.mu.RUnlock()
	return opts.Ingestion.RecurseTrusts
}

func (opts *RuntimeOptions) GetRecurseFeasibleOnly() bool {
	opts.mu.RLock()
	defer opts.mu.RUnlock()
	return opts.Ingestion.RecurseFeasibleOnly
}

func (opts *RuntimeOptions) GetIncludeACLs() bool {
	opts.mu.RLock()
	defer opts.mu.RUnlock()
	return opts.Ingestion.IncludeACLs
}

func (opts *RuntimeOptions) GetSearchForest() bool {
	opts.mu.RLock()
	defer opts.mu.RUnlock()
	return opts.Ingestion.SearchForest
}

func (opts *RuntimeOptions) GetLdapsToLdapFallback() bool {
	opts.mu.RLock()
	defer opts.mu.RUnlock()
	return opts.Ingestion.LdapsToLdapFallback
}

func (opts *RuntimeOptions) GetMergeRemote() bool {
	opts.mu.RLock()
	defer opts.mu.RUnlock()
	return opts.Conversion.MergeRemote
}

func (opts *RuntimeOptions) GetWriterBufsize() int {
	opts.mu.RLock()
	defer opts.mu.RUnlock()
	return opts.Conversion.WriterBufsize
}

func (opts *RuntimeOptions) GetCompressOutput() bool {
	opts.mu.RLock()
	defer opts.mu.RUnlock()
	return opts.Conversion.CompressOutput
}

func (opts *RuntimeOptions) GetCleanupAfterCompression() bool {
	opts.mu.RLock()
	defer opts.mu.RUnlock()
	return opts.Conversion.CleanupAfterCompression
}

// IsMethodEnabled checks if a specific collection method is enabled
func (opts *RuntimeOptions) IsMethodEnabled(method string) bool {
	opts.mu.RLock()
	defer opts.mu.RUnlock()
	for _, m := range opts.RemoteCollection.Methods {
		if m == method {
			return true
		}
	}
	return false
}

// GetQueries returns a copy of the query definitions
func (opts *RuntimeOptions) GetQueries() []QueryDefinition {
	opts.mu.RLock()
	defer opts.mu.RUnlock()
	queries := make([]QueryDefinition, len(opts.Ingestion.Queries))
	copy(queries, opts.Ingestion.Queries)
	return queries
}

// GetEnabledMethods returns a copy of the enabled methods list
func (opts *RuntimeOptions) GetEnabledMethods() []string {
	opts.mu.RLock()
	defer opts.mu.RUnlock()
	methods := make([]string, len(opts.RemoteCollection.Methods))
	copy(methods, opts.RemoteCollection.Methods)
	return methods
}

// Thread-safe setters
func (opts *RuntimeOptions) SetRecurseTrusts(enabled bool) {
	opts.mu.Lock()
	defer opts.mu.Unlock()
	opts.Ingestion.RecurseTrusts = enabled
}

func (opts *RuntimeOptions) SetIncludeACLs(enabled bool) {
	opts.mu.Lock()
	defer opts.mu.Unlock()
	opts.Ingestion.IncludeACLs = enabled
}

func (opts *RuntimeOptions) SetSearchForest(enabled bool) {
	opts.mu.Lock()
	defer opts.mu.Unlock()
	opts.Ingestion.SearchForest = enabled
}

func (opts *RuntimeOptions) SetLdapsToLdapFallback(enabled bool) {
	opts.mu.Lock()
	defer opts.mu.Unlock()
	opts.Ingestion.LdapsToLdapFallback = enabled
}

func (opts *RuntimeOptions) SetMergeRemote(enabled bool) {
	opts.mu.Lock()
	defer opts.mu.Unlock()
	opts.Conversion.MergeRemote = enabled
}

func (opts *RuntimeOptions) SetWriterBufsize(size int) {
	opts.mu.Lock()
	defer opts.mu.Unlock()
	opts.Conversion.WriterBufsize = size
}

func (opts *RuntimeOptions) SetCompressOutput(enabled bool) {
	opts.mu.Lock()
	defer opts.mu.Unlock()
	opts.Conversion.CompressOutput = enabled
}

func (opts *RuntimeOptions) SetCleanupAfterCompression(enabled bool) {
	opts.mu.Lock()
	defer opts.mu.Unlock()
	opts.Conversion.CleanupAfterCompression = enabled
}
