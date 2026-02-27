package network

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var KnownWebGLRendererParts = []string{
	"AMD",
	"ANGLE",
	"ASUS",
	"ATI",
	"ATI Radeon",
	"ATI Technologies Inc",
	"Adreno",
	"Android Emulator",
	"Apple",
	"Apple GPU",
	"Apple M1",
	"Chipset",
	"D3D11",
	"Direct3D",
	"Express Chipset",
	"GeForce",
	"Generation",
	"Generic Renderer",
	"Google",
	"Google SwiftShader",
	"Graphics",
	"Graphics Media Accelerator",
	"HD Graphics Family",
	"Intel",
	"Intel(R) HD Graphics",
	"Intel(R) UHD Graphics",
	"Iris",
	"KBL Graphics",
	"Mali",
	"Mesa",
	"Mesa DRI",
	"Metal",
	"Microsoft",
	"Microsoft Basic Render Driver",
	"Microsoft Corporation",
	"NVIDIA",
	"NVIDIA Corporation",
	"NVIDIAGameReadyD3D",
	"OpenGL",
	"OpenGL Engine",
	"Open Source Technology Center",
	"Parallels",
	"Parallels Display Adapter",
	"PCIe",
	"Plus Graphics",
	"PowerVR",
	"Pro Graphics",
	"Quadro",
	"Radeon",
	"Radeon Pro",
	"Radeon Pro Vega",
	"Samsung",
	"SSE2",
	"VMware",
	"VMware SVGA 3D",
	"Vega",
	"VirtualBox",
	"VirtualBox Graphics Adapter",
	"Vulkan",
	"Xe Graphics",
	"llvmpipe",
}

var KnownOsFonts = map[string][]string{
	"WINDOWS": {
		"Cambria Math",
		"Calibri",
		"MS Outlook",
		"HoloLens MDL2 Assets",
		"Segoe Fluent Icons",
	},
	"APPLE": {
		"Helvetica Neue",
		"Luminari",
		"PingFang HK Light",
		"InaiMathi Bold",
		"Galvji",
		"Chakra Petch",
	},
}

type RobotPattern struct {
	Pattern string `json:"pattern"`
}

var robotUserAgents []RobotPattern

func FetchRobotUserAgents() error {
	if len(robotUserAgents) > 0 {
		return nil
	}
	resp, err := http.Get("https://raw.githubusercontent.com/atmire/COUNTER-Robots/master/COUNTER_Robots_list.json")
	if err != nil {
		return fmt.Errorf("failed to fetch robot user agents: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read robot user agents body: %w", err)
	}

	err = json.Unmarshal(body, &robotUserAgents)
	if err != nil {
		// attempt to parse as array of objects
		return fmt.Errorf("failed to unmarshal robot user agents: %w", err)
	}

	return nil
}

// SimpleUAParse is a placeholder for a port of ua-parser-js
// For a complete implementation, use an external module like "github.com/mssola/user_agent" or similar.
func SimpleUAParse(userAgent string) (osName string, deviceType string, browserName string) {
	ua := strings.ToLower(userAgent)

	if strings.Contains(ua, "windows") {
		osName = "Windows"
	} else if strings.Contains(ua, "mac os x") {
		osName = "macOS"
	} else if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") {
		osName = "iOS"
	} else if strings.Contains(ua, "android") {
		osName = "Android"
	} else if strings.Contains(ua, "linux") {
		osName = "Linux"
	}

	if strings.Contains(ua, "mobile") {
		deviceType = "mobile"
	} else if strings.Contains(ua, "tablet") || strings.Contains(ua, "ipad") {
		deviceType = "tablet"
	} else {
		deviceType = "desktop"
	}

	if strings.Contains(ua, "firefox") || strings.Contains(ua, "fxios") {
		browserName = "Firefox"
	} else if strings.Contains(ua, "edg") {
		browserName = "Edge"
	} else if strings.Contains(ua, "chrome") || strings.Contains(ua, "crios") {
		browserName = "Chrome"
	} else if strings.Contains(ua, "safari") {
		browserName = "Safari"
	}

	return osName, deviceType, browserName
}

func ValidateRecord(record map[string]any) (map[string]any, bool) {
	if err := FetchRobotUserAgents(); err != nil {
		fmt.Printf("Warning: couldn't fetch robot agents list: %v\n", err)
	}

	bfMap, ok := record["browserFingerprint"].(map[string]any)
	if !ok {
		return nil, false
	}
	rfMap, ok := record["requestFingerprint"].(map[string]any)
	if !ok {
		return nil, false
	}

	userAgent, ok := bfMap["userAgent"].(string)
	if !ok {
		return nil, false
	}

	headers, ok := rfMap["headers"].(map[string]any)
	if !ok {
		return nil, false
	}

	// Robot check
	botMatch, _ := regexp.MatchString(`(?i)(bot|bots|slurp|spider|crawler|crawl)\b`, userAgent)
	if botMatch {
		return nil, false
	}
	for _, robot := range robotUserAgents {
		match, _ := regexp.MatchString("(?i)"+robot.Pattern, userAgent)
		if match {
			return nil, false
		}
	}

	// Simple UA parse
	osName, deviceType, browserName := SimpleUAParse(userAgent)
	isDesktop := deviceType != "mobile" && deviceType != "wearable" && deviceType != "tablet"

	var knownOsFonts []string
	if strings.HasPrefix(osName, "Windows") {
		knownOsFonts = KnownOsFonts["WINDOWS"]
	} else if osName == "macOS" || osName == "iOS" {
		knownOsFonts = KnownOsFonts["APPLE"]
	}

	userAgentHeaderMatch := false
	for k, v := range headers {
		if strings.ToLower(k) == "user-agent" {
			if vs, ok := v.(string); ok && vs == userAgent {
				userAgentHeaderMatch = true
			}
			break
		}
	}

	if !userAgentHeaderMatch {
		return nil, false
	}

	// Product sub check
	if productSub, ok := bfMap["productSub"].(string); ok {
		if strings.Contains(browserName, "Firefox") {
			if productSub != "20100101" {
				return nil, false
			}
		} else {
			if productSub != "20030107" {
				return nil, false
			}
		}
	}

	// Vendor check
	if vendor, ok := bfMap["vendor"].(string); ok {
		if strings.Contains(browserName, "Firefox") && vendor != "" {
			return nil, false
		} else if strings.Contains(browserName, "Safari") && vendor != "Apple Computer, Inc." {
			return nil, false
		}
	}

	// Fonts check
	if fontsData, ok := bfMap["fonts"].([]any); ok && len(fontsData) > 0 && len(knownOsFonts) > 0 {
		fontFound := false
		for _, fontAny := range fontsData {
			if fontStr, ok := fontAny.(string); ok {
				for _, knownHostFont := range knownOsFonts {
					if fontStr == knownHostFont {
						fontFound = true
						break
					}
				}
			}
		}
		if !fontFound {
			return nil, false
		}
	}

	// Screen check
	if screenData, ok := bfMap["screen"].(map[string]any); ok {
		widthAny, wOk := screenData["width"]
		heightAny, hOk := screenData["height"]
		if wOk && hOk {
			var w, h float64
			if wFloat, ok := widthAny.(float64); ok {
				w = wFloat
			}
			if hFloat, ok := heightAny.(float64); ok {
				h = hFloat
			}

			if w > 0 && h > 0 {
				maxScreen := w
				minScreen := h
				if h > w {
					maxScreen = h
					minScreen = w
				}

				if isDesktop && (maxScreen < 512 || minScreen < 384) {
					return nil, false
				}
				if maxScreen < 480 || maxScreen > 7680 || minScreen < 320 || minScreen > 4320 {
					return nil, false
				}
			}
		}
	}

	// Flatten output to match desired structure from TS
	output := make(map[string]any)
	for k, v := range record {
		output[k] = v
	}

	// Adding user agent props to output, as Zod transform does
	userAgentProps := map[string]any{
		"isDesktop":    isDesktop,
		"knownOsFonts": knownOsFonts,
		"parsedUserAgent": map[string]any{
			"browser": map[string]any{"name": browserName},
			"device":  map[string]any{"type": deviceType},
			"os":      map[string]any{"name": osName},
		},
	}
	output["userAgentProps"] = userAgentProps

	// add userAgent string based on browserFingerprint.userAgent
	output["userAgent"] = userAgent

	return output, true
}
