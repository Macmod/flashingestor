package core

import (
	"log"
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
		log.Fatal("Failed to create `"+dirs.LDAP+"` folder:", err)
	}

	if err := os.MkdirAll(dirs.Remote, 0755); err != nil {
		log.Fatal("Failed to create `"+dirs.Remote+"` folder:", err)
	}

	if err := os.MkdirAll(dirs.BloodHound, 0755); err != nil {
		log.Fatal("Failed to create `"+dirs.BloodHound+"` folder:", err)
	}

	return dirs, nil
}
