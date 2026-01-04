package core

// ConversionUpdate represents a progress update from the conversion process
type ConversionUpdate struct {
	Step      int
	Status    string
	Processed int
	Total     int
	Percent   float64
	Speed     string
	AvgSpeed  string
	ETA       string
	Elapsed   string
}

// SetupConversion is a signal to setup the conversion table
type SetupConversion struct{}

// RemoteCollectionUpdate represents a progress update from the remote collection process
type RemoteCollectionUpdate struct {
	Step      int
	Status    string
	Processed int
	Total     int
	Percent   float64
	Speed     string
	AvgSpeed  string
	Success   string
	ETA       string
	Elapsed   string
}
