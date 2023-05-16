// Package osinfo provides a cross-platform way to identify the hardware your
// code is running on.
package osinfo

// Copyright: (c) 2019 Blackfire SAS (https://blackfire.io)
// License:   MIT
// Author:    Karl Stenerud

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"regexp"
	"runtime"
)

// Note: This must be updated with every new Mac OS release.
//       There is no other reliable way to get the "marketing" name from a mac.
var macCodeNames = map[string]string{
	// Mininum 10.10 (https://github.com/golang/go/wiki/MinimumRequirements)
	"10.10": "Yosemite",
	"10.11": "El Capitan",
	"10.12": "Sierra",
	"10.13": "High Sierra",
	"10.14": "Mojave",
	"10.15": "Catalina",
	"10.16": "Big Sur", // Big Sur is both 10.16 and 11.0
	"11.0":  "Big Sur", // See https://en.wikipedia.org/wiki/MacOS_Big_Sur#Development_history
	"12.0":  "Monterey",
}

type OSInfo struct {
	Family       string
	Architecture string
	ID           string
	Name         string
	Codename     string
	Version      string
	Build        string
}

// GetOSInfo gets information about the current operating system.
// The OSInfo object will always be valid, even on error.
// If an error occurs, OSInfo will contain at least the Family and Architecture
// fields, with a good chance that Name will also contain something.
func GetOSInfo() (*OSInfo, error) {
	// To add support for a new system, create a new getOSInfoXYZ() function and
	// then add a case statement for its GOOS value, listed here:
	//   https://github.com/golang/go/blob/master/src/go/build/syslist.go

	// getOSInfoXYZ() guidelines:
	// * Prefer text files (such as /etc/os-release) or /proc to commands.
	// * Prefer simple, well established commands (such as uname).
	// * Any command must work on a pristine system with nothing else installed.
	// * Always use the full path to a command for security reasons.

	switch runtime.GOOS {
	case "windows":
		return getOSInfoWindows()
	case "darwin":
		return getOSInfoMac()
	case "linux":
		return getOSInfoLinux()
	case "freebsd":
		return getOSInfoFreeBSD()
	default:
		return getOSInfoUnknown()
	}
}

func readTextFile(path string) (result string, err error) {
	var bytes []byte
	bytes, err = ioutil.ReadFile(path)
	if err == nil {
		result = string(bytes)
	}
	return
}

func hexToInt(hexString string) (int, error) {
	if len(hexString) < 3 || hexString[:2] != "0x" {
		return 0, fmt.Errorf("%v: Not a hex number", hexString)
	}
	hexString = hexString[2:]
	if len(hexString)&1 == 1 {
		hexString = "0" + hexString
	}
	dst := make([]byte, len(hexString)/2)
	bytesWritten, err := hex.Decode(dst, []byte(hexString))
	if err != nil {
		return 0, err
	}
	dst = dst[:bytesWritten]
	accumulator := 0
	for _, b := range dst {
		accumulator = accumulator<<8 | int(b)
	}
	return accumulator, nil
}

func extractRegistryString(id string, regCommandOutput string) (string, error) {
	rePortion := `.*\s+REG_\w+\s+(.+)`
	re := regexp.MustCompile(fmt.Sprintf("%v%v", id, rePortion))
	found := re.FindStringSubmatch(regCommandOutput)
	if len(found) == 0 {
		return "", fmt.Errorf("Error: Could not parse reg query result: %v", regCommandOutput)
	}

	return found[1], nil
}

func extractRegistryInt(id string, regCommandOutput string) (int, error) {
	stringValue, err := extractRegistryString(id, regCommandOutput)
	if err != nil {
		return 0, err
	}
	return hexToInt(stringValue)
}

func getRegistryRaw(id string) (string, error) {
	return readCommandOutput(`C:\Windows\system32\reg.exe`, `query`, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, `/v`, id)
}

func populateFromRuntime(info *OSInfo) {
	info.Architecture = runtime.GOARCH
	info.Family = runtime.GOOS
}

func parseEtcOSRelease(info *OSInfo, contents string) {
	keyvalues := parseKeyValues(contents)

	if v, ok := keyvalues["ID"]; ok && info.ID == "" {
		info.ID = v
	}
	if v, ok := keyvalues["VERSION_ID"]; ok && info.Version == "" {
		info.Version = v
	}
	if v, ok := keyvalues["NAME"]; ok && info.Name == "" {
		info.Name = v
	}
	if v, ok := keyvalues["VERSION_CODENAME"]; ok && info.Codename == "" {
		info.Codename = v
	}
}

func parseEtcLSBRelease(info *OSInfo, contents string) {
	keyvalues := parseKeyValues(contents)

	if v, ok := keyvalues["DISTRIB_ID"]; ok && info.ID == "" {
		info.ID = v
	}
	if v, ok := keyvalues["DISTRIB_RELEASE"]; ok && info.Version == "" {
		info.Version = v
	}
	if v, ok := keyvalues["DISTRIB_CODENAME"]; ok && info.Codename == "" {
		info.Codename = v
	}
	if v, ok := keyvalues["DISTRIB_DESCRIPTION"]; ok && info.Name == "" {
		info.Name = v
	}
}

func parseKeyValues(contents string) (kvmap map[string]string) {
	kvmap = make(map[string]string)
	re := regexp.MustCompile(`\b(.+)="?([^"\n]*)"?`)
	for _, found := range re.FindAllStringSubmatch(contents, -1) {
		kvmap[found[1]] = found[2]
	}
	return
}

func parseMacSWVers(info *OSInfo, productVersion, buildVersion string) error {
	info.Version = productVersion
	info.Build = buildVersion

	re := regexp.MustCompile(`\d+\.\d+`)
	version := re.FindString(info.Version)
	if len(version) == 0 {
		return fmt.Errorf("Could not parse product version [%v]", info.Version)
	}
	codeName, ok := macCodeNames[version]
	if ok {
		info.Codename = codeName
	} else {
		info.Codename = "unknown"
	}

	return nil
}

func parseFreeBSDUname(info *OSInfo, unameV string) error {
	re := regexp.MustCompile(`(\S+)\s+(\S+)\s+(\S+).*`)
	found := re.FindStringSubmatch(unameV)
	if len(found) == 0 {
		return fmt.Errorf("Error: Could not parse result from uname -v [%v]", unameV)
	}

	info.Name = found[1]
	info.Version = found[2]
	info.Build = found[3]

	return nil
}

func getRegistryString(id string) (string, error) {
	raw, err := getRegistryRaw(id)
	if err != nil {
		return "", err
	}

	return extractRegistryString(id, raw)
}

func getRegistryInt(id string) (int, error) {
	raw, err := getRegistryRaw(id)
	if err != nil {
		return 0, err
	}

	return extractRegistryInt(id, raw)
}

func getOSInfoWindows() (info *OSInfo, err error) {
	info = new(OSInfo)
	populateFromRuntime(info)
	info.ID = "windows"

	var versionMajor int
	var versionMinor int

	// Only Windows 10+ has this
	versionMinor, err = getRegistryInt("CurrentMinorVersionNumber")
	versionMajor, err = getRegistryInt("CurrentMajorVersionNumber")
	if err != nil {
		err = nil
		versionMajor = 0
		versionMinor = 0
	}

	info.Name, err = getRegistryString("ProductName")
	if err != nil {
		return
	}

	var servicePack string
	servicePack, err = getRegistryString("CSDVersion")
	if err == nil {
		info.Name = info.Name + " " + servicePack
	}

	if versionMajor == 0 {
		info.Version, err = getRegistryString("CurrentVersion")
		if err != nil {
			return
		}
	} else {
		info.Version = fmt.Sprintf("%v.%v", versionMajor, versionMinor)
	}

	info.Codename, err = getRegistryString("ReleaseID")
	if err != nil {
		info.Codename = ""
	}

	info.Build, err = getRegistryString("CurrentBuild")
	return
}

func getOSInfoLinux() (info *OSInfo, err error) {
	info = new(OSInfo)
	populateFromRuntime(info)

	var contents string
	if contents, err = readTextFile("/etc/os-release"); err == nil {
		parseEtcOSRelease(info, contents)
	}

	lastError := err

	if contents, err = readTextFile("/etc/lsb-release"); err == nil {
		parseEtcLSBRelease(info, contents)
	}

	// Only propagate an error if both files failed to load
	if lastError == nil {
		err = nil
	}

	return
}

func getOSInfoFreeBSD() (info *OSInfo, err error) {
	info = new(OSInfo)
	populateFromRuntime(info)
	info.ID = "freebsd"

	var contents string
	contents, err = readCommandOutput("/usr/bin/uname", "-v")
	if err != nil {
		return
	}
	err = parseFreeBSDUname(info, contents)
	return
}

func getOSInfoMac() (info *OSInfo, err error) {
	info = new(OSInfo)
	populateFromRuntime(info)
	info.ID = "darwin"
	info.Name = "Mac OS X"

	var productVersion string
	productVersion, err = readCommandOutput("/usr/bin/sw_vers", "-productVersion")
	if err != nil {
		return
	}
	var buildVersion string
	buildVersion, err = readCommandOutput("/usr/bin/sw_vers", "-buildVersion")
	if err != nil {
		return
	}

	err = parseMacSWVers(info, productVersion, buildVersion)
	return
}

func getOSInfoUnknown() (info *OSInfo, err error) {
	info = new(OSInfo)
	populateFromRuntime(info)
	info.ID = "unknown"
	info.Name = "unknown"
	info.Version = "unknown"

	// Try to fill with contents of `uname`.
	var contents string
	contents, err = readCommandOutput("/usr/bin/uname")
	if err == nil {
		info.Name = contents
	}

	err = fmt.Errorf("%v: Unhandled OS", runtime.GOOS)

	return
}
