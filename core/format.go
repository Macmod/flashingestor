package core

import (
	"fmt"
	"strings"
	"time"
)

// FormatFileSize formats bytes into human-readable size string.
func FormatFileSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	size := float64(bytes)
	units := []string{"KB", "MB", "GB"}
	for _, unit := range units {
		size /= 1024
		if size < 1024 || unit == "GB" {
			return fmt.Sprintf("%.1f %s", size, unit)
		}
	}
	return fmt.Sprintf("%.1f GB", size)
}

// FormatDuration formats a duration into a human-readable string
func FormatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	var parts []string

	if hours > 0 {
		if hours == 1 {
			parts = append(parts, "1 hour")
		} else {
			parts = append(parts, fmt.Sprintf("%d hours", hours))
		}
	}

	if minutes > 0 {
		if minutes == 1 {
			parts = append(parts, "1 minute")
		} else {
			parts = append(parts, fmt.Sprintf("%d minutes", minutes))
		}
	}

	if seconds > 0 {
		if seconds == 1 {
			parts = append(parts, "1 second")
		} else {
			parts = append(parts, fmt.Sprintf("%d seconds", seconds))
		}
	}

	if len(parts) == 0 {
		return "0 seconds"
	}

	if len(parts) == 1 {
		return parts[0]
	}

	if len(parts) == 2 {
		return parts[0] + " and " + parts[1]
	}

	// For 3 parts: "X hours, Y minutes and Z seconds"
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}
