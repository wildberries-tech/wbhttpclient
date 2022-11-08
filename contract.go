package wbhttpclient

import (
	"time"
)

// httpMetrics is an interface for writing default http client metrics
type httpMetrics interface {
	// Inc increases requests counter by one. method, code and path are label values for "method", "status" and "path" fields
	Inc(metod, code, path string)

	// WriteTiming writes time elapsed since the startTime.
	// method, code and path are label values for "method", "status" and "path" fields
	WriteTiming(start time.Time, method, code, path string)
}
