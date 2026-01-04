// Package bloodhound provides BloodHound data processing and collection capabilities.
// It handles conversion of LDAP data to BloodHound format and remote data collection
// from Active Directory environments.
package bloodhound

import (
	"fmt"
	"net"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/Macmod/flashingestor/config"
	"github.com/Macmod/flashingestor/core"
)

// CURRENT_BH_VER is the BloodHound JSON schema version this tool generates.
const CURRENT_BH_VER = 5

// directoryPaths maps logical names to AD PKI and configuration container DNs.
var directoryPaths = map[string]string{
	"EnterpriseCALocation": "CN=Enrollment Services,CN=Public Key Services,CN=Services",
	"RootCALocation":       "CN=Certification Authorities,CN=Public Key Services,CN=Services",
	"AIACALocation":        "CN=AIA,CN=Public Key Services,CN=Services",
	"CertTemplateLocation": "CN=Certificate Templates,CN=Public Key Services,CN=Services",
	"NTAuthStoreLocation":  "CN=NTAuthCertificates,CN=Public Key Services,CN=Services",
	"PKILocation":          "CN=Public Key Services,CN=Services",
	"ConfigLocation":       "CN=Configuration",
	"OIDContainerLocation": "CN=OID,CN=Public Key Services,CN=Services",
}

// BHFilesMap maps logical file keys to their physical filenames for LDAP ingestion data.
type BHFilesMap struct {
	Files map[string]string
}

// NewBHFilesMap creates a new file map with standard LDAP data file names.
func NewBHFilesMap() BHFilesMap {
	files := map[string]string{
		"schema":        "Schema.msgpack",
		"domains":       "Domains.msgpack",
		"trusts":        "Trusts.msgpack",
		"groups":        "Groups.msgpack",
		"gpos":          "GroupPolicies.msgpack",
		"ous":           "OrganizationalUnits.msgpack",
		"containers":    "Containers.msgpack",
		"users":         "Users.msgpack",
		"computers":     "Computers.msgpack",
		"configuration": "Configuration.msgpack",
	}

	return BHFilesMap{
		Files: files,
	}
}

func (bp *BHFilesMap) GetPaths(ldapFolder string, fileKey string) ([]string, error) {
	fileName, ok := bp.Files[fileKey]
	if !ok {
		return nil, fmt.Errorf("file key %s not found", fileKey)
	}

	var entries []string
	var err error
	if fileKey == "schema" || fileKey == "configuration" {
		entries, err = filepath.Glob(filepath.Join(ldapFolder, "FOREST+*", fileName))
	} else {
		entries, err = filepath.Glob(filepath.Join(ldapFolder, "*", fileName))
	}

	return entries, err
}

// BH orchestrates BloodHound data conversion and remote collection operations.
// It maintains state for ingestion paths, output locations, and runtime configuration.
type BH struct {
	FilesMap                     BHFilesMap
	Timestamp                    string
	LdapFolder                   string
	OutputFolder                 string
	ActiveFolder                 string
	Log                          chan<- string
	RuntimeOptions               *config.RuntimeOptions
	Resolver                     *net.Resolver
	RemoteWorkers                int
	DNSWorkers                   int
	RemoteTimeout                time.Duration
	RemoteWriteBuff              int
	RemoteComputerCollection     map[string]*RemoteCollectionResult
	RemoteEnterpriseCACollection map[string]*EnterpriseCARemoteCollectionResult
	ConversionUpdates            chan<- core.ConversionUpdate
	RemoteCollectionUpdates      chan<- core.RemoteCollectionUpdate
	abortFlag                    atomic.Bool
	generatedFiles               []string
	writers                      map[string]*BHFormatWriter // Indexed by "timestamp_kind"
}

// GetPaths retrieves the file paths for a given logical file key within the LDAP data folder.
func (bh *BH) GetPaths(fileKey string) ([]string, error) {
	return bh.FilesMap.GetPaths(bh.LdapFolder, fileKey)
}

// Init initializes the BloodHound processor with necessary parameters
func (bh *BH) Init(ldapFolder string, activeFolder string, outputFolder string, customResolver *net.Resolver, remoteWorkers int, dnsWorkers int, remoteTimeout time.Duration, runtimeOptions *config.RuntimeOptions, log chan<- string) {
	bh.FilesMap = NewBHFilesMap()

	bh.RemoteTimeout = remoteTimeout
	bh.RemoteWorkers = remoteWorkers
	bh.DNSWorkers = dnsWorkers
	bh.RemoteWriteBuff = 1000
	bh.RuntimeOptions = runtimeOptions
	bh.Resolver = customResolver

	bh.OutputFolder = outputFolder
	bh.ActiveFolder = activeFolder
	bh.LdapFolder = ldapFolder
	bh.Log = log
}

// GetCurrentWriter creates a new BloodHound format writer for the specified object kind
// NOTE: Not thread-safe
func (bh *BH) GetCurrentWriter(kind string) (*BHFormatWriter, error) {
	// Initialize writers map if needed
	if bh.writers == nil {
		bh.writers = make(map[string]*BHFormatWriter)
	}

	// Create cache key from timestamp and kind
	cacheKey := bh.Timestamp + "_" + kind

	// Check if writer already exists
	if writer, exists := bh.writers[cacheKey]; exists {
		return writer, nil
	}

	// Create new writer
	outputFilepath := filepath.Join(bh.OutputFolder, bh.Timestamp+"_"+kind+".json")
	bh.generatedFiles = append(bh.generatedFiles, outputFilepath)
	bufferSize := bh.RuntimeOptions.GetWriterBufsize()
	writer, err := NewBHFormatWriter(outputFilepath, kind, CURRENT_BH_VER, bufferSize)
	if err != nil {
		return nil, err
	}

	// Cache the writer
	bh.writers[cacheKey] = writer
	return writer, nil
}

// ResetAbortFlag clears any pending abort request.
func (bh *BH) ResetAbortFlag() {
	bh.abortFlag.Store(false)
}

// RequestAbort sets the abort flag if it has not been set already.
func (bh *BH) RequestAbort() bool {
	return bh.abortFlag.CompareAndSwap(false, true)
}

// IsAborted reports whether an abort was requested.
func (bh *BH) IsAborted() bool {
	return bh.abortFlag.Load()
}
