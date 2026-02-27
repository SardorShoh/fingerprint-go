package header

import (
	"math/rand"
	"strings"
)

// ShuffleArray randomly shuffles a slice of strings
func ShuffleArray(arr []string) []string {
	shuffled := make([]string, len(arr))
	copy(shuffled, arr)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	return shuffled
}

func GetUserAgent(headers map[string]string) string {
	for k, v := range headers {
		if strings.ToLower(k) == "user-agent" {
			return v
		}
	}
	return ""
}

func GetBrowser(userAgent string) string {
	userAgent = strings.ToLower(userAgent)
	if strings.Contains(userAgent, "edg") {
		return "edge"
	}
	if strings.Contains(userAgent, "chrome") && !strings.Contains(userAgent, "edg") {
		return "chrome"
	}
	if strings.Contains(userAgent, "safari") && !strings.Contains(userAgent, "chrome") {
		return "safari"
	}
	if strings.Contains(userAgent, "firefox") {
		return "firefox"
	}
	return ""
}

// GetBrowsersFromQuery is a placeholder for `browserslist` equivalent in Go.
// For now, returning the supported browsers.
func GetBrowsersFromQuery(query string) []string {
	return SupportedBrowsers
}
