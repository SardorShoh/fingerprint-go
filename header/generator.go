package header

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"fingerprint-go/bayesian"
	"fingerprint-go/network"
)

type HttpBrowserObject struct {
	Name           string
	Version        []int
	CompleteString string
	HttpVersion    string
}

type BrowserSpecification struct {
	Name        string
	MinVersion  int
	MaxVersion  int
	HttpVersion string
}

type HeaderGeneratorOptions struct {
	Browsers         []any // Can be string or BrowserSpecification
	BrowserListQuery string
	OperatingSystems []string
	Devices          []string
	Locales          []string
	HttpVersion      string
	Strict           bool
}

type HeaderGenerator struct {
	globalOptions          HeaderGeneratorOptions
	browserListQuery       string
	inputGeneratorNetwork  *bayesian.Network
	headerGeneratorNetwork *bayesian.Network
	uniqueBrowsers         []HttpBrowserObject
	headersOrder           map[string][]string
	relaxationOrder        []string
}

func DefaultHeaderGeneratorOptions() HeaderGeneratorOptions {
	return HeaderGeneratorOptions{
		Browsers:         []any{"chrome", "edge", "firefox", "safari"},
		OperatingSystems: SupportedOperatingSystems,
		Devices:          []string{"desktop"},
		Locales:          []string{"en-US"},
		HttpVersion:      "2",
		BrowserListQuery: "",
		Strict:           false,
	}
}

func prepareHttpBrowserObject(httpBrowserString string) HttpBrowserObject {
	parts := strings.Split(httpBrowserString, "|")
	browserString := parts[0]
	httpVersion := ""
	if len(parts) > 1 {
		httpVersion = parts[1]
	}

	var browserObject HttpBrowserObject
	if browserString == MissingValueDatasetToken {
		browserObject = HttpBrowserObject{Name: MissingValueDatasetToken}
	} else {
		browserObject = prepareBrowserObject(browserString)
	}

	browserObject.HttpVersion = httpVersion
	browserObject.CompleteString = httpBrowserString
	return browserObject
}

func prepareBrowserObject(browserString string) HttpBrowserObject {
	nameVersionSplit := strings.Split(browserString, "/")
	name := nameVersionSplit[0]
	var preparedVersion []int
	if len(nameVersionSplit) > 1 {
		versionSplit := strings.Split(nameVersionSplit[1], ".")
		for _, vPart := range versionSplit {
			i, _ := strconv.Atoi(vPart)
			preparedVersion = append(preparedVersion, i)
		}
	}

	return HttpBrowserObject{
		Name:           name,
		Version:        preparedVersion,
		CompleteString: browserString,
	}
}

func NewHeaderGenerator(options *HeaderGeneratorOptions, dataFilesPath string) (*HeaderGenerator, error) {
	opts := DefaultHeaderGeneratorOptions()
	if options != nil {
		if options.Browsers != nil {
			opts.Browsers = options.Browsers
		}
		if options.BrowserListQuery != "" {
			opts.BrowserListQuery = options.BrowserListQuery
		}
		if options.OperatingSystems != nil {
			opts.OperatingSystems = options.OperatingSystems
		}
		if options.Devices != nil {
			opts.Devices = options.Devices
		}
		if options.Locales != nil {
			opts.Locales = options.Locales
		}
		if options.HttpVersion != "" {
			opts.HttpVersion = options.HttpVersion
		}
		opts.Strict = options.Strict
	}

	gen := &HeaderGenerator{
		relaxationOrder: []string{"locales", "devices", "operatingSystems", "browsers", "browserListQuery"},
	}

	// Prepare browsers setup
	preparedBrowsers := gen.prepareBrowsersConfig(opts.Browsers, opts.BrowserListQuery, opts.HttpVersion)

	gen.globalOptions = opts
	// Reassign with properly prepared structs if necessary, but we'll use preparedBrowsers below

	gen.uniqueBrowsers = make([]HttpBrowserObject, 0)

	// Load headers order
	headersOrderData, err := os.ReadFile(filepath.Join(dataFilesPath, "headers-order.json"))
	if err == nil {
		json.Unmarshal(headersOrderData, &gen.headersOrder)
	} else {
		gen.headersOrder = make(map[string][]string)
	}

	// Load browser helper file
	browserHelperData, err := os.ReadFile(filepath.Join(dataFilesPath, "browser-helper-file.json"))
	if err == nil {
		var uniqueBrowserStrings []string
		json.Unmarshal(browserHelperData, &uniqueBrowserStrings)
		for _, browserString := range uniqueBrowserStrings {
			if browserString != MissingValueDatasetToken {
				gen.uniqueBrowsers = append(gen.uniqueBrowsers, prepareHttpBrowserObject(browserString))
			}
		}
	}

	gen.inputGeneratorNetwork = bayesian.NewNetwork(filepath.Join(dataFilesPath, "input-network-definition.zip"))
	gen.headerGeneratorNetwork = bayesian.NewNetwork(filepath.Join(dataFilesPath, "header-network-definition.zip"))

	// We only use preparedBrowsers logic to validate or configure later.
	_ = preparedBrowsers

	return gen, nil
}

func (g *HeaderGenerator) prepareBrowsersConfig(browsers []any, browserListQuery string, httpVersion string) []BrowserSpecification {
	var finalBrowsers []any

	if browserListQuery != "" {
		bq := GetBrowsersFromQuery(browserListQuery)
		for _, b := range bq {
			finalBrowsers = append(finalBrowsers, b)
		}
	} else {
		finalBrowsers = browsers
	}

	var results []BrowserSpecification
	for _, b := range finalBrowsers {
		switch v := b.(type) {
		case string:
			results = append(results, BrowserSpecification{Name: v, HttpVersion: httpVersion})
		case BrowserSpecification:
			if v.HttpVersion == "" {
				v.HttpVersion = httpVersion
			}
			results = append(results, v)
		}
	}
	return results
}

func (g *HeaderGenerator) GetHeaders(options *HeaderGeneratorOptions, requestDependentHeaders map[string]string, userAgentValues []string) (map[string]string, error) {
	headerOptions := g.globalOptions
	if options != nil {
		if options.Browsers != nil {
			headerOptions.Browsers = options.Browsers
		}
		if options.BrowserListQuery != "" {
			headerOptions.BrowserListQuery = options.BrowserListQuery
		}
		if options.OperatingSystems != nil {
			headerOptions.OperatingSystems = options.OperatingSystems
		}
		if options.Devices != nil {
			headerOptions.Devices = options.Devices
		}
		if options.Locales != nil {
			headerOptions.Locales = options.Locales
		}
		if options.HttpVersion != "" {
			headerOptions.HttpVersion = options.HttpVersion
		}
		headerOptions.Strict = options.Strict
	}

	possibleAttributeValues := g.getPossibleAttributeValues(&headerOptions)

	var http1Constraints, http2Constraints map[string][]string
	if len(userAgentValues) > 0 {
		http1Constraints = network.GetConstraintClosure(g.headerGeneratorNetwork, map[string][]string{"User-Agent": userAgentValues})
		http2Constraints = network.GetConstraintClosure(g.headerGeneratorNetwork, map[string][]string{"user-agent": userAgentValues})
	}

	inputConstraints := make(map[string][]string)
	for key, values := range possibleAttributeValues {
		if key == "*BROWSER_HTTP" {
			var filtered []string
			for _, x := range values {
				parts := strings.Split(x, "|")
				browserName := parts[0]
				httpV := ""
				if len(parts) > 1 {
					httpV = parts[1]
				}

				httpValues := http2Constraints
				if httpV == "1" || http2Constraints == nil || len(http2Constraints) == 0 {
					httpValues = http1Constraints
				}

				if httpValues == nil || slices.Contains(httpValues["*BROWSER"], browserName) {
					filtered = append(filtered, x)
				}
			}
			inputConstraints[key] = filtered
			continue
		}

		var filtered []string
		for _, x := range values {
			included1 := http1Constraints != nil && slices.Contains(http1Constraints[key], x)
			included2 := http2Constraints != nil && slices.Contains(http2Constraints[key], x)
			if (http1Constraints == nil && http2Constraints == nil) || included1 || included2 {
				filtered = append(filtered, x)
			}
		}
		inputConstraints[key] = filtered
	}

	inputSample := g.inputGeneratorNetwork.GenerateConsistentSampleWhenPossible(inputConstraints)

	if len(inputSample) == 0 {
		if headerOptions.HttpVersion == "1" {
			newOpts := headerOptions
			newOpts.HttpVersion = "2"
			headers2, err := g.GetHeaders(&newOpts, requestDependentHeaders, userAgentValues)
			if err != nil {
				return nil, err
			}

			pascalize := func(name string) string {
				parts := strings.Split(name, "-")
				for i, p := range parts {
					if len(p) > 0 {
						parts[i] = string(unicode.ToUpper(rune(p[0]))) + strings.ToLower(p[1:])
					}
				}
				return strings.Join(parts, "-")
			}

			converted := make(map[string]string)
			for name, value := range headers2 {
				if strings.HasPrefix(name, "sec-ch-ua") {
					converted[name] = value
					continue
				}
				if name == "dnt" || name == "rtt" || name == "ect" {
					converted[strings.ToUpper(name)] = value
					continue
				}
				converted[pascalize(name)] = value
			}

			return g.OrderHeaders(converted, nil), nil
		}

		relaxationIndex := -1
		if options != nil {
			for i, key := range g.relaxationOrder {
				var set bool
				switch key {
				case "locales":
					set = options.Locales != nil
				case "devices":
					set = options.Devices != nil
				case "operatingSystems":
					set = options.OperatingSystems != nil
				case "browsers":
					set = options.Browsers != nil
				case "browserListQuery":
					set = options.BrowserListQuery != ""
				}
				if set {
					relaxationIndex = i
					break
				}
			}
		}

		if headerOptions.Strict || relaxationIndex == -1 {
			return nil, errors.New("No headers based on this input can be generated. Please relax or change some of the requirements you specified.")
		}

		relaxedOptions := *options
		switch g.relaxationOrder[relaxationIndex] {
		case "locales":
			relaxedOptions.Locales = nil
		case "devices":
			relaxedOptions.Devices = nil
		case "operatingSystems":
			relaxedOptions.OperatingSystems = nil
		case "browsers":
			relaxedOptions.Browsers = nil
		case "browserListQuery":
			relaxedOptions.BrowserListQuery = ""
		}
		return g.GetHeaders(&relaxedOptions, requestDependentHeaders, userAgentValues)
	}

	generatedSample := g.headerGeneratorNetwork.GenerateSample(inputSample)

	generatedHttpAndBrowser := prepareHttpBrowserObject(generatedSample[BrowserHttpNodeName])
	secFetchAttributeNames := Http2SecFetchAttributes
	acceptLanguageFieldName := "accept-language"

	if generatedHttpAndBrowser.HttpVersion != "2" {
		acceptLanguageFieldName = "Accept-Language"
		secFetchAttributeNames = Http1SecFetchAttributes
	}

	generatedSample[acceptLanguageFieldName] = g.getAcceptLanguageField(headerOptions.Locales)

	isChrome := generatedHttpAndBrowser.Name == "chrome"
	isFirefox := generatedHttpAndBrowser.Name == "firefox"
	isEdge := generatedHttpAndBrowser.Name == "edge"

	genV0 := 0
	if len(generatedHttpAndBrowser.Version) > 0 {
		genV0 = generatedHttpAndBrowser.Version[0]
	}

	hasSecFetch := (isChrome && genV0 >= 76) || (isFirefox && genV0 >= 90) || (isEdge && genV0 >= 79)

	if hasSecFetch {
		generatedSample[secFetchAttributeNames["site"]] = "same-site"
		generatedSample[secFetchAttributeNames["mode"]] = "navigate"
		generatedSample[secFetchAttributeNames["user"]] = "?1"
		generatedSample[secFetchAttributeNames["dest"]] = "document"
	}

	for attribute, val := range generatedSample {
		if strings.ToLower(attribute) == "connection" && val == "close" {
			delete(generatedSample, attribute)
		}
		if strings.HasPrefix(attribute, "*") || val == MissingValueDatasetToken {
			delete(generatedSample, attribute)
		}
	}

	for k, v := range requestDependentHeaders {
		generatedSample[k] = v
	}

	return g.OrderHeaders(generatedSample, g.headersOrder[generatedHttpAndBrowser.Name]), nil
}

func (g *HeaderGenerator) OrderHeaders(headers map[string]string, order []string) map[string]string {
	if order == nil || len(order) == 0 {
		order = g.getOrderFromUserAgent(headers)
	}

	orderedSample := make(map[string]string)
	for _, attribute := range order {
		if val, ok := headers[attribute]; ok {
			// In Go, map iteration is unordered, but we can't enforce order natively in map[string]string
			// Assuming consumer might sort or just expects map. We return the map directly.
			// True ordered headers require []struct{Key, Value string} in Go
			orderedSample[attribute] = val
		}
	}

	for attribute, val := range headers {
		if !slices.Contains(order, attribute) {
			orderedSample[attribute] = val
		}
	}

	return orderedSample
}

func (g *HeaderGenerator) getOrderFromUserAgent(headers map[string]string) []string {
	userAgent := GetUserAgent(headers)
	browser := GetBrowser(userAgent)

	if browser == "" {
		return nil
	}
	return g.headersOrder[browser]
}

func (g *HeaderGenerator) getPossibleAttributeValues(headerOptions *HeaderGeneratorOptions) map[string][]string {
	browsers := g.prepareBrowsersConfig(headerOptions.Browsers, headerOptions.BrowserListQuery, headerOptions.HttpVersion)

	browserHttpOptions := g.getBrowserHttpOptions(browsers)

	possibleAttributeValues := make(map[string][]string)
	possibleAttributeValues[BrowserHttpNodeName] = browserHttpOptions
	possibleAttributeValues[OperatingSystemNodeName] = headerOptions.OperatingSystems

	if len(headerOptions.Devices) > 0 {
		possibleAttributeValues[DeviceNodeName] = headerOptions.Devices
	}

	return possibleAttributeValues
}

func (g *HeaderGenerator) getBrowserHttpOptions(browsers []BrowserSpecification) []string {
	var browserHttpOptions []string
	for _, browser := range browsers {
		for _, browserOption := range g.uniqueBrowsers {
			if browser.Name == browserOption.Name {
				browserMajorVersion := 0
				if len(browserOption.Version) > 0 {
					browserMajorVersion = browserOption.Version[0]
				}

				if (browser.MinVersion == 0 || browser.MinVersion <= browserMajorVersion) &&
					(browser.MaxVersion == 0 || browser.MaxVersion >= browserMajorVersion) &&
					(browser.HttpVersion == "0" || browser.HttpVersion == "" || browser.HttpVersion == browserOption.HttpVersion) {
					browserHttpOptions = append(browserHttpOptions, browserOption.CompleteString)
				}
			}
		}
	}
	return browserHttpOptions
}

func (g *HeaderGenerator) getAcceptLanguageField(localesFromOptions []string) string {
	locales := make([]string, len(localesFromOptions))
	copy(locales, localesFromOptions)

	var highLevelLocales []string
	for _, locale := range locales {
		if !strings.Contains(locale, "-") {
			highLevelLocales = append(highLevelLocales, locale)
		}
	}

	for _, locale := range locales {
		if !slices.Contains(highLevelLocales, locale) {
			highLevelEquivalentPresent := false
			for _, highLevelLocale := range highLevelLocales {
				if strings.Contains(locale, highLevelLocale) {
					highLevelEquivalentPresent = true
					break
				}
			}
			if !highLevelEquivalentPresent {
				highLevelLocales = append(highLevelLocales, locale)
			}
		}
	}

	highLevelLocales = ShuffleArray(highLevelLocales)
	locales = ShuffleArray(locales)

	var localesInAddingOrder []string
	for _, highLevelLocale := range highLevelLocales {
		for _, locale := range locales {
			if strings.Contains(locale, highLevelLocale) && !slices.Contains(highLevelLocales, locale) {
				localesInAddingOrder = append(localesInAddingOrder, locale)
			}
		}
		localesInAddingOrder = append(localesInAddingOrder, highLevelLocale)
	}

	if len(localesInAddingOrder) == 0 {
		return ""
	}

	acceptLanguageFieldValue := localesInAddingOrder[0]
	for x := 1; x < len(localesInAddingOrder); x++ {
		q := 1.0 - (float64(x) * 0.1)
		acceptLanguageFieldValue += "," + localesInAddingOrder[x] + ";q=" + strconv.FormatFloat(q, 'f', 1, 64)
	}

	return acceptLanguageFieldValue
}
