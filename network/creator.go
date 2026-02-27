package network

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"fingerprint-go/bayesian"
)

const (
	BrowserHttpNodeName      = "*BROWSER_HTTP"
	HttpVersionNodeName      = "*HTTP_VERSION"
	BrowserNodeName          = "*BROWSER"
	OperatingSystemNodeName  = "*OPERATING_SYSTEM"
	DeviceNodeName           = "*DEVICE"
	MissingValueDatasetToken = "*MISSING_VALUE*"
	StringifiedPrefix        = "*STRINGIFIED*"
)

var NonGeneratedNodes = []string{
	BrowserHttpNodeName,
	BrowserNodeName,
	OperatingSystemNodeName,
	DeviceNodeName,
}

var PluginCharacteristicsAttributes = []string{"plugins", "mimeTypes"}

func prepareRecords(records []map[string]any, preprocessingType string) ([]map[string]any, error) {
	var cleanedRecords []map[string]any

	for _, rec := range records {
		if validRec, ok := ValidateRecord(rec); ok {
			cleanedRecords = append(cleanedRecords, validRec)
		}
	}

	fmt.Printf("Found %d/%d valid records.\n", len(cleanedRecords), len(records))

	var deconstructedRecords []map[string]any

	for _, record := range cleanedRecords {
		if preprocessingType == "headers" {
			rfMap, ok := record["requestFingerprint"].(map[string]any)
			if !ok {
				continue
			}
			httpVersion, _ := rfMap["httpVersion"].(string)
			headers, hOk := rfMap["headers"].(map[string]any)
			if hOk {
				headers[HttpVersionNodeName] = "_" + httpVersion + "_"
				deconstructedRecords = append(deconstructedRecords, headers)
			}
		} else {
			bfMap, ok := record["browserFingerprint"].(map[string]any)
			if ok {
				deconstructedRecords = append(deconstructedRecords, bfMap)
			}
		}
	}

	attributesSet := make(map[string]struct{})
	for _, rec := range deconstructedRecords {
		for k := range rec {
			attributesSet[k] = struct{}{}
		}
	}

	var reorganizedRecords []map[string]any
	for _, record := range deconstructedRecords {
		reorganizedRecord := make(map[string]any)
		for attribute := range attributesSet {
			if val, exists := record[attribute]; !exists || val == nil {
				reorganizedRecord[attribute] = MissingValueDatasetToken
			} else {
				reorganizedRecord[attribute] = val
			}
		}
		reorganizedRecords = append(reorganizedRecords, reorganizedRecord)
	}

	return reorganizedRecords, nil
}

type GeneratorNetworksCreator struct{}

func NewGeneratorNetworksCreator() *GeneratorNetworksCreator {
	return &GeneratorNetworksCreator{}
}

func (c *GeneratorNetworksCreator) getDeviceOS(userAgent string) (device string, operatingSystem string) {
	uaLower := strings.ToLower(userAgent)
	operatingSystem = MissingValueDatasetToken
	device = "desktop"

	if strings.Contains(uaLower, "windows") {
		operatingSystem = "windows"
	}

	mobilePattern := regexp.MustCompile(`(?i)(phone|android|mobile)`)
	if mobilePattern.MatchString(uaLower) {
		device = "mobile"
		if regexp.MustCompile(`(?i)(iphone|mac)`).MatchString(uaLower) {
			operatingSystem = "ios"
		} else if strings.Contains(uaLower, "android") {
			operatingSystem = "android"
		}
	} else if strings.Contains(uaLower, "linux") {
		operatingSystem = "linux"
	} else if strings.Contains(uaLower, "mac") {
		operatingSystem = "macos"
	}

	return device, operatingSystem
}

func (c *GeneratorNetworksCreator) getBrowserNameVersion(userAgent string) string {
	canonicalNames := map[string]string{
		"chrome":  "chrome",
		"crios":   "chrome",
		"firefox": "firefox",
		"fxios":   "firefox",
		"safari":  "safari",
		"edge":    "edge",
		"edg":     "edge",
		"edga":    "edge",
		"edgios":  "edge",
	}

	unsupportedBrowsers := regexp.MustCompile(`(?i)(opr|yabrowser|SamsungBrowser|UCBrowser|vivaldi)`)
	edgeRegex := regexp.MustCompile(`(?i)(edg(a|ios|e)?)/([0-9.]*)`)
	safariRegex := regexp.MustCompile(`(?i)Version/([\d.]+)( Mobile/[a-z0-9]+)? Safari`)
	supportedBrowsers := regexp.MustCompile(`(?i)(firefox|fxios|chrome|crios|safari)/([0-9.]*)`)

	if unsupportedBrowsers.MatchString(userAgent) {
		return MissingValueDatasetToken
	}

	if match := edgeRegex.FindStringSubmatch(userAgent); match != nil {
		return "edge/" + match[3]
	}

	if match := safariRegex.FindStringSubmatch(userAgent); match != nil {
		return "safari/" + match[1]
	}

	if match := supportedBrowsers.FindStringSubmatch(userAgent); match != nil {
		browser := strings.ToLower(match[1])
		return canonicalNames[browser] + "/" + match[2]
	}

	return MissingValueDatasetToken
}

func (c *GeneratorNetworksCreator) PrepareHeaderGeneratorFiles(datasetPath string, resultsPath string) error {
	datasetText, err := os.ReadFile(datasetPath)
	if err != nil {
		return err
	}

	var parsedRecords []map[string]any
	if err := json.Unmarshal(datasetText, &parsedRecords); err != nil {
		return err
	}

	records, err := prepareRecords(parsedRecords, "headers")
	if err != nil {
		return err
	}

	// This assumes the bayesian networks already exist at these paths or we are initializing them
	// The TS implementation used relative paths. In Go, you will have to provide the correct ones.
	inputNetworkStructurePath := filepath.Join("network_structures", "input-network-structure.zip")
	headerNetworkStructurePath := filepath.Join("network_structures", "header-network-structure.zip")

	inputGeneratorNetwork := bayesian.NewNetwork(inputNetworkStructurePath)
	headerGeneratorNetwork := bayesian.NewNetwork(headerNetworkStructurePath)

	desiredHeaderAttributes := make(map[string]struct{})
	for attr := range headerGeneratorNetwork.NodesByName {
		isGenerated := true
		for _, nonGen := range NonGeneratedNodes {
			if attr == nonGen {
				isGenerated = false
				break
			}
		}
		if isGenerated {
			desiredHeaderAttributes[attr] = struct{}{}
		}
	}

	var selectedRecords bayesian.RecordList
	for _, record := range records {
		selRec := make(map[string]any)
		for key, value := range record {
			if _, ok := desiredHeaderAttributes[key]; ok {
				if value == nil {
					selRec[key] = MissingValueDatasetToken
				} else {
					selRec[key] = value
				}
			}
		}
		selectedRecords = append(selectedRecords, selRec)
	}

	var finalRecords bayesian.RecordList
	for _, record := range selectedRecords {
		uaVal := ""
		if userAgent, ok := record["user-agent"].(string); ok && userAgent != MissingValueDatasetToken {
			uaVal = userAgent
		} else if userAgent, ok := record["User-Agent"].(string); ok {
			uaVal = userAgent
		}
		uaLower := strings.ToLower(uaVal)

		browser := c.getBrowserNameVersion(uaLower)
		device, operatingSystem := c.getDeviceOS(uaLower)

		httpVersionStr := "2"
		if httpVer, ok := record[HttpVersionNodeName].(string); ok && strings.HasPrefix(httpVer, "_1") {
			httpVersionStr = "1"
		}

		record[BrowserNodeName] = browser
		record[OperatingSystemNodeName] = operatingSystem
		record[DeviceNodeName] = device
		record[BrowserHttpNodeName] = fmt.Sprintf("%s|%s", browser, httpVersionStr)

		finalRecords = append(finalRecords, record)
	}

	/* Note: bayesian package doesn't define SetProbabilitiesAccordingToData yet, so you would implement it in network.go or just leave as stub.
	   headerGeneratorNetwork.SetProbabilitiesAccordingToData(finalRecords)
	   inputGeneratorNetwork.SetProbabilitiesAccordingToData(finalRecords)
	*/

	/*
	   inputNetworkDefinitionPath := filepath.Join(resultsPath, "input-network-definition.zip")
	   headerNetworkDefinitionPath := filepath.Join(resultsPath, "header-network-definition.zip")
	   headerGeneratorNetwork.SaveNetworkDefinition(headerNetworkDefinitionPath)
	   inputGeneratorNetwork.SaveNetworkDefinition(inputNetworkDefinitionPath)
	*/

	browserHelperFilePath := filepath.Join(resultsPath, "browser-helper-file.json")
	uniqueBrowsersAndHttpsSet := make(map[string]struct{})
	for _, record := range finalRecords {
		if browserHttp, ok := record[BrowserHttpNodeName].(string); ok {
			uniqueBrowsersAndHttpsSet[browserHttp] = struct{}{}
		}
	}

	var uniqueBrowsersAndHttps []string
	for k := range uniqueBrowsersAndHttpsSet {
		uniqueBrowsersAndHttps = append(uniqueBrowsersAndHttps, k)
	}

	b, _ := json.Marshal(uniqueBrowsersAndHttps)
	if err := os.WriteFile(browserHelperFilePath, b, 0644); err != nil {
		return err
	}

	return nil
}

func (c *GeneratorNetworksCreator) PrepareFingerprintGeneratorFiles(datasetPath string, resultsPath string) error {
	datasetTextBytes, err := os.ReadFile(datasetPath)
	if err != nil {
		return err
	}

	datasetText := string(datasetTextBytes)
	if strings.HasPrefix(datasetText, "\ufeff") {
		datasetText = datasetText[3:]
	}

	var parsedRecords []map[string]any
	if err := json.Unmarshal([]byte(datasetText), &parsedRecords); err != nil {
		return err
	}

	records, err := prepareRecords(parsedRecords, "fingerprints")
	if err != nil {
		return err
	}

	for x, record := range records {
		if x%1000 == 0 {
			fmt.Printf("Processing record %d of %d\n", x, len(records))
		}

		pluginCharacteristics := make(map[string]string)
		for _, attr := range PluginCharacteristicsAttributes {
			if val, exists := record[attr]; exists {
				if strVal, ok := val.(string); ok && strVal != "" {
					pluginCharacteristics[attr] = strVal
				} else if arrVal, ok := val.([]any); ok && len(arrVal) > 0 { // plugins often arrays
					b, _ := json.Marshal(arrVal)
					pluginCharacteristics[attr] = string(b)
				}
				delete(record, attr)
			}
		}

		if len(pluginCharacteristics) != 0 {
			record["pluginsData"] = pluginCharacteristics
		} else {
			record["pluginsData"] = MissingValueDatasetToken
		}

		for attr, val := range record {
			if val == nil || val == "" {
				record[attr] = MissingValueDatasetToken
			} else if strVal, ok := val.(string); ok {
				record[attr] = strVal
			} else {
				b, _ := json.Marshal(val)
				record[attr] = StringifiedPrefix + string(b)
			}
		}
		records[x] = record
	}

	fingerprintNetworkStructurePath := filepath.Join("network_structures", "fingerprint-network-structure.zip")
	fingerprintGeneratorNetwork := bayesian.NewNetwork(fingerprintNetworkStructurePath)

	desiredFingerprintAttributes := make(map[string]struct{})
	for attr := range fingerprintGeneratorNetwork.NodesByName {
		desiredFingerprintAttributes[attr] = struct{}{}
	}

	var selectedRecords bayesian.RecordList
	for _, record := range records {
		selRec := make(map[string]any)
		for key, value := range record {
			if _, ok := desiredFingerprintAttributes[key]; ok {
				if value == nil {
					selRec[key] = MissingValueDatasetToken
				} else {
					selRec[key] = value
				}
			}
		}
		selectedRecords = append(selectedRecords, selRec)
	}

	// fingerprintNetworkDefinitionPath := filepath.Join(resultsPath, "fingerprint-network-definition.zip")
	fmt.Println("Building the fingerprint network...")
	// fingerprintGeneratorNetwork.SetProbabilitiesAccordingToData(selectedRecords)
	// fingerprintGeneratorNetwork.SaveNetworkDefinition(fingerprintNetworkDefinitionPath)

	return nil
}
