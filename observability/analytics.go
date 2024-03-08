package observability

import "time"

type Analytics interface {
	TrackScan(bool, ScanMetrics)
}

type ScanMetrics struct {
	lastScanStartTime time.Time
	lastScanFileCount int
}

func NewScanMetrics(lastScanStartTime time.Time, lastScanFileCount int) ScanMetrics {
	return ScanMetrics{
		lastScanStartTime: lastScanStartTime,
		lastScanFileCount: lastScanFileCount,
	}
}

func (s ScanMetrics) GetDuration() time.Duration {
	return time.Since(s.lastScanStartTime)
}

func (s ScanMetrics) GetLastScanFileCount() int {
	return s.lastScanFileCount
}

func (s ScanMetrics) SetLastScanFileCount(lastScanFileCount int) {
	s.lastScanFileCount = lastScanFileCount
}
