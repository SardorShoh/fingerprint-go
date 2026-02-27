package header

var SupportedBrowsers = []string{
	"chrome",
	"firefox",
	"safari",
	"edge",
}

var SupportedOperatingSystems = []string{
	"windows",
	"macos",
	"linux",
	"android",
	"ios",
}

var SupportedDevices = []string{
	"desktop",
	"mobile",
}

var SupportedHttpVersions = []string{
	"1",
	"2",
}

const (
	BrowserHttpNodeName      string = "*BROWSER_HTTP"
	OperatingSystemNodeName  string = "*OPERATING_SYSTEM"
	DeviceNodeName           string = "*DEVICE"
	MissingValueDatasetToken string = "*MISSING_VALUE*"
)

var Http1SecFetchAttributes = map[string]string{
	"mode": "Sec-Fetch-Mode",
	"dest": "Sec-Fetch-Dest",
	"site": "Sec-Fetch-Site",
	"user": "Sec-Fetch-User",
}

var Http2SecFetchAttributes = map[string]string{
	"mode": "sec-fetch-mode",
	"dest": "sec-fetch-dest",
	"site": "sec-fetch-site",
	"user": "sec-fetch-user",
}
