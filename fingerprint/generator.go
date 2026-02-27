package fingerprint

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"fingerprint-go/bayesian"
	"fingerprint-go/header"
)

type ScreenFingerprint struct {
	AvailHeight      float64 `json:"availHeight"`
	AvailWidth       float64 `json:"availWidth"`
	AvailTop         float64 `json:"availTop"`
	AvailLeft        float64 `json:"availLeft"`
	ColorDepth       float64 `json:"colorDepth"`
	Height           float64 `json:"height"`
	PixelDepth       float64 `json:"pixelDepth"`
	Width            float64 `json:"width"`
	DevicePixelRatio float64 `json:"devicePixelRatio"`
	PageXOffset      float64 `json:"pageXOffset"`
	PageYOffset      float64 `json:"pageYOffset"`
	InnerHeight      float64 `json:"innerHeight"`
	OuterHeight      float64 `json:"outerHeight"`
	OuterWidth       float64 `json:"outerWidth"`
	InnerWidth       float64 `json:"innerWidth"`
	ScreenX          float64 `json:"screenX"`
	ClientWidth      float64 `json:"clientWidth"`
	ClientHeight     float64 `json:"clientHeight"`
	HasHDR           bool    `json:"hasHDR"`
}

type Brand struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

type UserAgentData struct {
	Brands          []Brand `json:"brands"`
	Mobile          bool    `json:"mobile"`
	Platform        string  `json:"platform"`
	Architecture    string  `json:"architecture"`
	Bitness         string  `json:"bitness"`
	FullVersionList []Brand `json:"fullVersionList"`
	Model           string  `json:"model"`
	PlatformVersion string  `json:"platformVersion"`
	UaFullVersion   string  `json:"uaFullVersion"`
}

type ExtraProperties struct {
	VendorFlavors        []string `json:"vendorFlavors"`
	IsBluetoothSupported bool     `json:"isBluetoothSupported"`
	GlobalPrivacyControl any      `json:"globalPrivacyControl"`
	PdfViewerEnabled     bool     `json:"pdfViewerEnabled"`
	InstalledApps        []any    `json:"installedApps"`
}

type NavigatorFingerprint struct {
	UserAgent           string          `json:"userAgent"`
	UserAgentData       UserAgentData   `json:"userAgentData"`
	Language            string          `json:"language"`
	Languages           []string        `json:"languages"`
	Platform            string          `json:"platform"`
	DeviceMemory        *float64        `json:"deviceMemory,omitempty"`
	HardwareConcurrency int             `json:"hardwareConcurrency"`
	MaxTouchPoints      *int            `json:"maxTouchPoints,omitempty"`
	Product             string          `json:"product"`
	ProductSub          string          `json:"productSub"`
	Vendor              string          `json:"vendor"`
	VendorSub           string          `json:"vendorSub"`
	DoNotTrack          string          `json:"doNotTrack"`
	AppCodeName         string          `json:"appCodeName"`
	AppName             string          `json:"appName"`
	AppVersion          string          `json:"appVersion"`
	Oscpu               string          `json:"oscpu"`
	ExtraProperties     ExtraProperties `json:"extraProperties"`
	Webdriver           string          `json:"webdriver"`
}

type VideoCard struct {
	Renderer string `json:"renderer"`
	Vendor   string `json:"vendor"`
}

type Fingerprint struct {
	Screen            ScreenFingerprint    `json:"screen"`
	Navigator         NavigatorFingerprint `json:"navigator"`
	VideoCodecs       map[string]string    `json:"videoCodecs"`
	AudioCodecs       map[string]string    `json:"audioCodecs"`
	PluginsData       map[string]string    `json:"pluginsData"`
	Battery           map[string]string    `json:"battery,omitempty"`
	VideoCard         VideoCard            `json:"videoCard"`
	MultimediaDevices []string             `json:"multimediaDevices"`
	Fonts             []string             `json:"fonts"`
	MockWebRTC        bool                 `json:"mockWebRTC"`
	Slim              bool                 `json:"slim,omitempty"`
}

type BrowserFingerprintWithHeaders struct {
	Headers     map[string]string `json:"headers"`
	Fingerprint Fingerprint       `json:"fingerprint"`
}

type FingerprintScreenOptions struct {
	MinWidth  *float64
	MaxWidth  *float64
	MinHeight *float64
	MaxHeight *float64
}

type FingerprintGeneratorOptions struct {
	*header.HeaderGeneratorOptions
	Screen     *FingerprintScreenOptions
	MockWebRTC bool
	Slim       bool
}

type FingerprintGenerator struct {
	*header.HeaderGenerator
	fingerprintGeneratorNetwork *bayesian.Network
	fingerprintGlobalOptions    *FingerprintGeneratorOptions
}

func NewFingerprintGenerator(options *FingerprintGeneratorOptions, dataFilesPath string) (*FingerprintGenerator, error) {
	var headerOpts *header.HeaderGeneratorOptions
	if options != nil {
		headerOpts = options.HeaderGeneratorOptions
	}

	headerGen, err := header.NewHeaderGenerator(headerOpts, dataFilesPath)
	if err != nil {
		return nil, err
	}

	gen := &FingerprintGenerator{
		HeaderGenerator: headerGen,
	}

	if options == nil {
		gen.fingerprintGlobalOptions = &FingerprintGeneratorOptions{}
	} else {
		gen.fingerprintGlobalOptions = &FingerprintGeneratorOptions{
			Screen:     options.Screen,
			MockWebRTC: options.MockWebRTC,
			Slim:       options.Slim,
		}
	}

	gen.fingerprintGeneratorNetwork = bayesian.NewNetwork(filepath.Join(dataFilesPath, "fingerprint-network-definition.zip"))

	return gen, nil
}

func (g *FingerprintGenerator) GetFingerprint(options *FingerprintGeneratorOptions, requestDependentHeaders map[string]string) (*BrowserFingerprintWithHeaders, error) {
	filteredValues := make(map[string][]string)

	optToUse := &FingerprintGeneratorOptions{
		Screen:     g.fingerprintGlobalOptions.Screen,
		MockWebRTC: g.fingerprintGlobalOptions.MockWebRTC,
		Slim:       g.fingerprintGlobalOptions.Slim,
	}
	optToUse.HeaderGeneratorOptions = &header.HeaderGeneratorOptions{} // need to merge properly, simplify for now

	if options != nil {
		if options.Screen != nil {
			optToUse.Screen = options.Screen
		}
		optToUse.MockWebRTC = options.MockWebRTC
		optToUse.Slim = options.Slim
		// merge header options if needed
		optToUse.HeaderGeneratorOptions = options.HeaderGeneratorOptions
	}

	var partialCSP map[string][]string
	if optToUse.Screen != nil {
		extensiveScreen := true
		if extensiveScreen {
			var possibleScreens []string
			if screenNode, ok := g.fingerprintGeneratorNetwork.NodesByName["screen"]; ok {
				for _, screenString := range screenNode.Definition.PossibleValues {
					if !strings.Contains(screenString, STRINGIFIED_PREFIX) {
						continue
					}
					parts := strings.SplitN(screenString, STRINGIFIED_PREFIX, 2)
					if len(parts) < 2 {
						continue
					}

					var screen ScreenFingerprint
					if err := json.Unmarshal([]byte(parts[1]), &screen); err == nil {
						minW, maxW, minH, maxH := 0.0, 1e5, 0.0, 1e5
						if optToUse.Screen.MinWidth != nil {
							minW = *optToUse.Screen.MinWidth
						}
						if optToUse.Screen.MaxWidth != nil {
							maxW = *optToUse.Screen.MaxWidth
						}
						if optToUse.Screen.MinHeight != nil {
							minH = *optToUse.Screen.MinHeight
						}
						if optToUse.Screen.MaxHeight != nil {
							maxH = *optToUse.Screen.MaxHeight
						}

						if screen.Width >= minW && screen.Width <= maxW && screen.Height >= minH && screen.Height <= maxH {
							possibleScreens = append(possibleScreens, screenString)
						}
					}
				}
				filteredValues["screen"] = possibleScreens
			}
		}

		closure, err := bayesian.GetConstraintClosure(g.fingerprintGeneratorNetwork, filteredValues)
		if err != nil {
			if optToUse.HeaderGeneratorOptions != nil && optToUse.HeaderGeneratorOptions.Strict {
				return nil, err
			}
			delete(filteredValues, "screen")
		} else {
			partialCSP = closure
		}
	}

	for generateRetries := 0; generateRetries < 10; generateRetries++ {
		var userAgentValues []string
		if partialCSP != nil && partialCSP["userAgent"] != nil {
			userAgentValues = partialCSP["userAgent"]
		}

		headers, err := g.HeaderGenerator.GetHeaders(optToUse.HeaderGeneratorOptions, requestDependentHeaders, userAgentValues)
		if err != nil {
			continue // retry or fallback
		}

		userAgent := ""
		if ua, ok := headers["User-Agent"]; ok {
			userAgent = ua
		} else if ua, ok := headers["user-agent"]; ok {
			userAgent = ua
		}

		filteredValues["userAgent"] = []string{userAgent}

		fingerprint := g.fingerprintGeneratorNetwork.GenerateConsistentSampleWhenPossible(filteredValues)
		if len(fingerprint) == 0 {
			continue
		}

		fingerprintRaw := make(map[string]any)
		for attribute, val := range fingerprint {
			if val == MISSING_VALUE_DATASET_TOKEN {
				fingerprintRaw[attribute] = nil
			} else if strings.HasPrefix(val, STRINGIFIED_PREFIX) {
				var parsed any
				if err := json.Unmarshal([]byte(val[len(STRINGIFIED_PREFIX):]), &parsed); err == nil {
					fingerprintRaw[attribute] = parsed
				} else {
					fingerprintRaw[attribute] = val
				}
			} else {
				fingerprintRaw[attribute] = val
			}
		}

		if fingerprintRaw["screen"] == nil {
			continue
		}

		acceptLanguageHeaderValue := ""
		if al, ok := headers["Accept-Language"]; ok {
			acceptLanguageHeaderValue = al
		} else if al, ok := headers["accept-language"]; ok {
			acceptLanguageHeaderValue = al
		}

		var acceptedLanguages []string
		for _, locale := range strings.Split(acceptLanguageHeaderValue, ",") {
			localeParts := strings.Split(locale, ";")
			if len(localeParts) > 0 {
				acceptedLanguages = append(acceptedLanguages, strings.TrimSpace(localeParts[0]))
			}
		}
		fingerprintRaw["languages"] = acceptedLanguages

		transformedFP := g.transformFingerprint(fingerprintRaw)
		transformedFP.MockWebRTC = optToUse.MockWebRTC
		transformedFP.Slim = optToUse.Slim

		return &BrowserFingerprintWithHeaders{
			Headers:     headers,
			Fingerprint: transformedFP,
		}, nil
	}

	return nil, fmt.Errorf("Failed to generate a consistent fingerprint after 10 attempts")
}

func (g *FingerprintGenerator) transformFingerprint(fingerprint map[string]any) Fingerprint {
	var fp Fingerprint
	b, err := json.Marshal(fingerprint)
	if err == nil {
		json.Unmarshal(b, &fp)
	}

	var navigator NavigatorFingerprint
	json.Unmarshal(b, &navigator) // grab shared fields

	deviceMemStr, _ := fingerprint["deviceMemory"].(string)
	parsedMemory, errMem := strconv.ParseFloat(deviceMemStr, 64)
	if errMem == nil {
		navigator.DeviceMemory = &parsedMemory
	} else {
		navigator.DeviceMemory = nil
	}

	hwConcStr, _ := fingerprint["hardwareConcurrency"].(string)
	parsedHw, _ := strconv.Atoi(hwConcStr)
	navigator.HardwareConcurrency = parsedHw

	maxTouchStr, _ := fingerprint["maxTouchPoints"].(string)
	if maxTouchStr != "" {
		parsedTouch, errTouch := strconv.Atoi(maxTouchStr)
		if errTouch == nil {
			navigator.MaxTouchPoints = &parsedTouch
		} else {
			zero := 0
			navigator.MaxTouchPoints = &zero
		}
	} else {
		zero := 0
		navigator.MaxTouchPoints = &zero
	}

	if langs, ok := fingerprint["languages"].([]string); ok {
		navigator.Languages = langs
		if len(langs) > 0 {
			navigator.Language = langs[0]
		}
	} else if langsAny, ok := fingerprint["languages"].([]any); ok {
		var langs []string
		for _, l := range langsAny {
			if strL, ok := l.(string); ok {
				langs = append(langs, strL)
			}
		}
		navigator.Languages = langs
		if len(langs) > 0 {
			navigator.Language = langs[0]
		}
	}

	fp.Navigator = navigator

	return fp
}
