package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Macmod/flashingestor/reader"
	"github.com/spf13/pflag"
)

var (
	version = "0.3.0"
)

func main() {
	showVersion := pflag.Bool("version", false, "Show version information and exit")
	outputFile := pflag.StringP("output", "o", "", "Output JSON file path (optional, defaults to input filename with .json extension)")
	indent := pflag.Bool("pretty", false, "Pretty-print JSON with indentation")
	pflag.Parse()

	if *showVersion {
		fmt.Printf("ingest2json %s\n", version)
		os.Exit(0)
	}

	// Input file is now a positional argument
	if pflag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: ./ingest2json <msgpack_file> [-o|--output <json_file>] [-pretty]")
		fmt.Fprintln(os.Stderr, "\nPositional arguments:")
		fmt.Fprintln(os.Stderr, "  <msgpack_file>    Input msgpack file path (required)")
		fmt.Fprintln(os.Stderr, "\nOptions:")
		pflag.PrintDefaults()
		os.Exit(1)
	}

	inputFile := pflag.Arg(0)

	// If output file not specified, use base filename in current directory
	if *outputFile == "" {
		baseName := filepath.Base(inputFile)
		ext := filepath.Ext(baseName)
		if strings.ToLower(ext) == ".msgpack" {
			*outputFile = strings.TrimSuffix(baseName, ext) + ".json"
		} else {
			*outputFile = baseName + ".json"
		}
	}

	log.Printf("📂 Opening msgpack file: %s", inputFile)

	mpReader, err := reader.NewMPReader(inputFile)
	if err != nil {
		log.Fatalf("❌ Failed to open msgpack file: %v", err)
	}
	defer mpReader.Close()

	outFile, err := os.Create(*outputFile)
	if err != nil {
		log.Fatalf("❌ Failed to create output file: %v", err)
	}
	defer outFile.Close()

	totalEntries, err := mpReader.ReadLength()
	if err != nil {
		log.Printf("🔍 File is not a fixed-size list, reading as stream of objects...")

		mpReader.Close()
		mpReader, err = reader.NewMPReader(inputFile)
		if err != nil {
			log.Fatalf("❌ Failed to reopen msgpack file: %v", err)
		}
		defer mpReader.Close()

		log.Printf("🔄 Streaming conversion to line-delimited JSON...")
		startTime := time.Now()

		encoder := json.NewEncoder(outFile)
		if *indent {
			encoder.SetIndent("", "  ")
		}

		count := 0
		for {
			var entry interface{}
			if err := mpReader.ReadEntry(&entry); err != nil {
				// End of stream
				break
			}

			// Encode the entry (encoder automatically adds newline)
			if err := encoder.Encode(entry); err != nil {
				log.Fatalf("❌ Failed to encode entry %d: %v", count, err)
			}

			count++
			if count%1000 == 0 {
				elapsed := time.Since(startTime)
				rate := float64(count) / elapsed.Seconds()
				log.Printf("⏳ Progress: %d entries - %.0f entries/sec", count, rate)
			}
		}

		duration := time.Since(startTime)
		log.Printf("✅ Successfully converted %d entries in %v", count, duration.Round(time.Millisecond))
		log.Printf("📝 Output file: %s", *outputFile)
		return
	}

	// It's a list - stream elements efficiently as line-delimited JSON
	log.Printf("📊 Found list with %d entries", totalEntries)
	log.Printf("🔄 Streaming conversion to line-delimited JSON...")

	startTime := time.Now()

	encoder := json.NewEncoder(outFile)
	if *indent {
		encoder.SetIndent("", "  ")
	}

	progressInterval := totalEntries / 20 // Report every 5%
	if progressInterval < 100 {
		progressInterval = 100
	}
	if progressInterval > 1000 {
		progressInterval = 1000
	}

	for i := 0; i < totalEntries; i++ {
		var entry interface{}
		if err := mpReader.ReadEntry(&entry); err != nil {
			log.Fatalf("❌ Failed to read entry %d: %v", i, err)
		}

		// Encode the entry (encoder automatically adds newline)
		if err := encoder.Encode(entry); err != nil {
			log.Fatalf("❌ Failed to encode entry %d: %v", i, err)
		}

		// Progress reporting
		if (i+1)%progressInterval == 0 || i == totalEntries-1 {
			percentage := float64(i+1) / float64(totalEntries) * 100
			elapsed := time.Since(startTime)
			rate := float64(i+1) / elapsed.Seconds()
			remaining := time.Duration(float64(totalEntries-i-1)/rate) * time.Second
			log.Printf("⏳ Progress: %d/%d (%.1f%%) - %.0f entries/sec - ETA: %v",
				i+1, totalEntries, percentage, rate, remaining.Round(time.Second))
		}
	}

	duration := time.Since(startTime)
	log.Printf("✅ Successfully converted %d entries in %v", totalEntries, duration.Round(time.Millisecond))
	log.Printf("📝 Output file: %s", *outputFile)
}
