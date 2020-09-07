package exprhelpers

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

var dataFile map[string][]string
var dataFileRegex map[string][]*regexp.Regexp

func Atof(x string) float64 {
	log.Debugf("debug atof %s", x)
	ret, err := strconv.ParseFloat(x, 64)
	if err != nil {
		log.Warningf("Atof : can't convert float '%s' : %v", x, err)
	}
	return ret
}

func Upper(s string) string {
	return strings.ToUpper(s)
}

func GetExprEnv(ctx map[string]interface{}) map[string]interface{} {
	var ExprLib = map[string]interface{}{
		"Atof":           Atof,
		"JsonExtract":    JsonExtract,
		"JsonExtractLib": JsonExtractLib,
		"File":           File,
		"RegexpInFile":   RegexpInFile,
		"Upper":          Upper,
	}
	for k, v := range ctx {
		ExprLib[k] = v
	}
	return ExprLib
}

func Init() error {
	dataFile = make(map[string][]string)
	dataFileRegex = make(map[string][]*regexp.Regexp)
	return nil
}

func FileInit(fileFolder string, filename string, fileType string) error {
	filepath := path.Join(fileFolder, filename)
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, ok := dataFile[filename]; !ok {
		dataFile[filename] = []string{}
	}
	if fileType == "" {
		fileType = "string"
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		switch fileType {
		case "regex", "regexp":
			dataFileRegex[filename] = append(dataFileRegex[filename], regexp.MustCompile(scanner.Text()))
		case "string":
			dataFile[filename] = append(dataFile[filename], scanner.Text())
		default:
			return fmt.Errorf("unknown data type '%s' for : '%s'", fileType, filename)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func File(filename string) []string {
	if _, ok := dataFile[filename]; ok {
		return dataFile[filename]
	}
	log.Errorf("file '%s' not found for expr library", filename)
	return []string{}
}

func RegexpInFile(data string, filename string) bool {
	if _, ok := dataFileRegex[filename]; ok {
		for _, re := range dataFileRegex[filename] {
			if re.Match([]byte(data)) {
				return true
			}
		}
	} else {
		log.Errorf("file '%s' not found for expr library", filename)
	}
	return false
}
