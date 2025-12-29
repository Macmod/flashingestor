package bloodhound

import (
	"fmt"
	"slices"
	"strings"
)

// formatFileSize converts a byte count to a human-readable size string (KB, MB, GB, TB)
func formatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB"}
	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), units[exp])
}

var filteredSids = []string{
	"S-1-5-3", "S-1-5-4", "S-1-5-6", "S-1-2", "S-1-2-0", "S-1-5-17", "S-1-5-18",
	"S-1-5-19", "S-1-5-20", "S-1-0-0", "S-1-0", "S-1-2-1",
}

// isSidFiltered checks if a SID should be excluded from processing (service accounts, NT AUTHORITY, etc.)
func isSidFiltered(sid string) bool {
	return slices.Contains(filteredSids, strings.ToUpper(sid)) ||
		strings.HasPrefix(sid, "S-1-5-80") ||
		strings.HasPrefix(sid, "S-1-5-82") ||
		strings.HasPrefix(sid, "S-1-5-90") ||
		strings.HasPrefix(sid, "S-1-5-96")
}
