package bloodhound

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// compressBloodhoundOutput packages all generated BloodHound JSON files into a timestamped zip archive
func (bh *BH) compressBloodhoundOutput() {
	if bh.IsAborted() {
		return
	}

	// Filter to only include files that were successfully generated and exist
	var filesToCompress []string
	for _, file := range bh.generatedFiles {
		if _, err := os.Stat(file); err == nil {
			filesToCompress = append(filesToCompress, file)
		}
	}

	if len(filesToCompress) == 0 {
		bh.Log <- "[yellow]🫠 No JSON files found to compress[-]"
		return
	}

	// Create zip file using the current timestamp
	zipPath := filepath.Join(bh.OutputFolder, bh.Timestamp+"_BloodHound.zip")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		bh.Log <- "❌ Error creating zip file: " + err.Error()
		return
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Initialize progress tracking
	startTime := time.Now()
	lastUpdateTime := startTime
	var lastCount int
	totalFiles := len(filesToCompress)

	// Add each JSON file to the zip
	for i, file := range filesToCompress {
		if bh.IsAborted() {
			return
		}

		if err := bh.addFileToZip(zipWriter, file); err != nil {
			bh.Log <- "❌ Error adding file to zip: " + err.Error()
			return
		}

		// Update progress
		count := i + 1
		elapsed := time.Since(startTime)

		// Calculate progress text
		var progressText string
		if count == totalFiles {
			progressText = fmt.Sprintf("[green]%d/%d[-]", count, totalFiles)
		} else {
			progressText = fmt.Sprintf("[blue]%d/%d[-]", count, totalFiles)
		}

		// Calculate percentage
		percentage := float64(count) / float64(totalFiles) * 100.0
		var percentText string
		if percentage >= 100.0 {
			percentText = fmt.Sprintf("[green]%.1f%%[-]", percentage)
		} else {
			percentText = fmt.Sprintf("[blue]%.1f%%[-]", percentage)
		}

		// Calculate current speed
		now := time.Now()
		timeSinceLastUpdate := now.Sub(lastUpdateTime).Seconds()
		var speedText string
		if timeSinceLastUpdate > 0 && count > lastCount {
			currentSpeed := float64(count-lastCount) / timeSinceLastUpdate
			speedText = fmt.Sprintf("%.1f/s", currentSpeed)
			lastUpdateTime = now
			lastCount = count
		} else {
			speedText = "-"
		}

		// Calculate average speed and ETA
		var avgSpeedText, etaText string
		if count > 0 && elapsed.Seconds() > 0 {
			avgSpeed := float64(count) / elapsed.Seconds()
			avgSpeedText = fmt.Sprintf("%.1f/s", avgSpeed)

			if count < totalFiles {
				remaining := totalFiles - count
				etaSeconds := float64(remaining) / avgSpeed
				etaDuration := time.Duration(etaSeconds * float64(time.Second))
				etaText = etaDuration.Round(time.Second).String()
			} else {
				etaText = "-"
			}
		} else {
			avgSpeedText = "-"
			etaText = "-"
		}

		// Update UI
		bh.UIApp.UpdateConversionRow(11, "", progressText, percentText, speedText, avgSpeedText, etaText, elapsed.Round(time.Second).String())
	}

	// Close the zip writer before getting file size
	if err := zipWriter.Close(); err != nil {
		bh.Log <- "❌ Error finalizing zip: " + err.Error()
		return
	}

	// Get zip file size
	if fileInfo, err := os.Stat(zipPath); err == nil {
		bh.Log <- fmt.Sprintf("✅ [green]BloodHound dump: \"%s\" (%s)[-]", zipPath, formatFileSize(fileInfo.Size()))
	} else {
		bh.Log <- fmt.Sprintf("🫠 [yellow]Problem saving \"%s\": %v[-]", zipPath, err)
	}

	// Cleanup original files if enabled
	if bh.RuntimeOptions.GetCleanupAfterCompression() {
		for _, file := range filesToCompress {
			if err := os.Remove(file); err != nil {
				bh.Log <- "[yellow]🫠 Could not remove \"" + filepath.Base(file) + "\":[-] " + err.Error()
			}
		}
		bh.Log <- fmt.Sprintf("🧹 Cleaned up %d original JSON files from \"%s\"", len(filesToCompress), bh.OutputFolder)
	}
}

// addFileToZip adds a single file to the zip archive
func (bh *BH) addFileToZip(zipWriter *zip.Writer, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create zip entry with just the filename (not full path)
	basename := filepath.Base(filePath)
	writer, err := zipWriter.Create(basename)
	if err != nil {
		return err
	}

	// Copy file contents to zip
	_, err = io.Copy(writer, file)
	return err
}
