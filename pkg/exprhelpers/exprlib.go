package exprhelpers

import (
	"bufio"
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

func StartsWith(s string, pref string) bool {
	return strings.HasPrefix(s, pref)
}

func EndsWith(s string, suff string) bool {
	return strings.HasSuffix(s, suff)
}

func GetExprEnv(ctx map[string]interface{}) map[string]interface{} {

	var ExprLib = map[string]interface{}{"Atof": Atof, "JsonExtract": JsonExtract, "JsonExtractLib": JsonExtractLib, "File": File, "RegexpInFile": RegexpInFile}
	for k, v := range ctx {
		ExprLib[k] = v
	}
	return ExprLib
}

func Init() error {
	log.Infof("Expr helper initiated")
	dataFile = make(map[string][]string)
	dataFileRegex = make(map[string][]*regexp.Regexp)
	return nil
}

func FileInit(fileFolder string, filename string) error {
	filepath := path.Join(fileFolder, filename)
	file, err := os.Open(filepath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	if _, ok := dataFile[filename]; !ok {
		dataFile[filename] = []string{}
	}
	fileType := "string"
	scanner := bufio.NewScanner(file)
	scanner.Scan()
	if scanner.Text() == "#type: regex" { // if file contains, it should have this header
		fileType = "regex"
	}
	for scanner.Scan() {
		if fileType == "regex" {
			dataFileRegex[filename] = append(dataFileRegex[filename], regexp.MustCompile(scanner.Text()))
		} else {
			dataFile[filename] = append(dataFile[filename], scanner.Text())
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
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
