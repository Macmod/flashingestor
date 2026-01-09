// Package core provides core functionality for flashingestor including
// directory management, logging, and event handling.
package core

import (
	"fmt"
	"os"
	"path/filepath"
)

// Directories holds paths to output directories.
type Directories struct {
	LDAP       string
	Remote     string
	BloodHound string
}

// SetupDirectories creates the required output directory structure.
func SetupDirectories(baseDir string) (*Directories, error) {
	dirs := &Directories{
		LDAP:       filepath.Join(baseDir, "ldap"),
		Remote:     filepath.Join(baseDir, "remote"),
		BloodHound: filepath.Join(baseDir, "bloodhound"),
	}

	if err := os.MkdirAll(dirs.LDAP, 0755); err != nil {
		return nil, fmt.Errorf("failed to create %s folder: %w", dirs.LDAP, err)
	}

	if err := os.MkdirAll(dirs.Remote, 0755); err != nil {
		return nil, fmt.Errorf("failed to create %s folder: %w", dirs.Remote, err)
	}

	if err := os.MkdirAll(dirs.BloodHound, 0755); err != nil {
		return nil, fmt.Errorf("failed to create %s folder: %w", dirs.BloodHound, err)
	}

	return dirs, nil
}
