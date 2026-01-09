package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Macmod/flashingestor/reader"
)

var (
	version = "0.1.0"
)

func main() {
	showVersion := flag.Bool("version", false, "Show version information and exit")
	inputFile := flag.String("in", "", "Input msgpack file path (required)")
	outputFile := flag.String("out", "", "Output JSON file path (required)")
	indent := flag.Bool("pretty", false, "Pretty-print JSON with indentation")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ingest2json %s\n", version)
		os.Exit(0)
	}

	if *inputFile == "" || *outputFile == "" {
		fmt.Fprintln(os.Stderr, "Usage: ./ingest2json -in <msgpack_file> -out <json_file> [-indent]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	log.Printf("📂 Opening msgpack file: %s", *inputFile)

	mpReader, err := reader.NewMPReader(*inputFile)
	if err != nil {
		log.Fatalf("❌ Failed to open msgpack file: %v", err)
	}
	defer mpReader.Close()

	outFile, err := os.Create(*outputFile)
	if err != nil {
		log.Fatalf("❌ Failed to create output file: %v", err)
	}
	defer outFile.Close()

	// Try to detect if it's a list or dictionary
	totalEntries, err := mpReader.ReadLength()
	if err != nil {
		// Not a list, try reading as dictionary or single object
		log.Printf("🔍 File is not a list, reading as object/dictionary...")

		mpReader.Close()
		mpReader, err = reader.NewMPReader(*inputFile)
		if err != nil {
			log.Fatalf("❌ Failed to reopen msgpack file: %v", err)
		}
		defer mpReader.Close()

		var data interface{}
		if err := mpReader.ReadEntry(&data); err != nil {
			log.Fatalf("❌ Failed to read msgpack data: %v", err)
		}

		log.Printf("✅ Data loaded into memory")
		log.Printf("🔄 Converting to JSON...")

		var jsonData []byte
		if *indent {
			jsonData, err = json.MarshalIndent(data, "", "  ")
		} else {
			jsonData, err = json.Marshal(data)
		}
		if err != nil {
			log.Fatalf("❌ Failed to marshal JSON: %v", err)
		}

		if _, err := outFile.Write(jsonData); err != nil {
			log.Fatalf("❌ Failed to write JSON: %v", err)
		}

		log.Printf("✅ Successfully converted to JSON: %s", *outputFile)
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
