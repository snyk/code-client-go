package observability

import "time"

// Analytics exposes different metric tracking functions.
type Analytics interface {
	TrackScan(bool, ScanMetrics)
}

// ScanMetrics contains various metrics about the Snyk Code scan.
type ScanMetrics struct {
	lastScanStartTime time.Time
	lastScanFileCount int
}

// NewScanMetrics is used to create a ScanMetrics object.
func NewScanMetrics(lastScanStartTime time.Time, lastScanFileCount int) ScanMetrics {
	return ScanMetrics{
		lastScanStartTime: lastScanStartTime,
		lastScanFileCount: lastScanFileCount,
	}
}

// GetDuration computes the duration since the last time a scan starter.
func (s ScanMetrics) GetDuration() time.Duration {
	return time.Since(s.lastScanStartTime)
}

// GetLastScanFileCount returns the count of files since the last scan.
func (s ScanMetrics) GetLastScanFileCount() int {
	return s.lastScanFileCount
}

// SetLastScanFileCount sets the count of files since the last scan.
func (s *ScanMetrics) SetLastScanFileCount(lastScanFileCount int) {
	s.lastScanFileCount = lastScanFileCount
}
