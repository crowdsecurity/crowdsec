package exprhelpers

import (
	"github.com/beevik/etree"
	log "github.com/sirupsen/logrus"
)

var pathCache = make(map[string]etree.Path)

func XMLGetAttributeValue(xmlString string, path string, attributeName string) string {

	if _, ok := pathCache[path]; !ok {
		compiledPath, err := etree.CompilePath(path)
		if err != nil {
			log.Errorf("Could not compile path %s: %s", path, err)
			return ""
		}
		pathCache[path] = compiledPath
	}

	compiledPath := pathCache[path]
	doc := etree.NewDocument()
	err := doc.ReadFromString(xmlString)
	if err != nil {
		log.Tracef("Could not parse XML: %s", err)
		return ""
	}
	elem := doc.FindElementPath(compiledPath)
	if elem == nil {
		log.Debugf("Could not find element %s", path)
		return ""
	}
	attr := elem.SelectAttr(attributeName)
	if attr == nil {
		log.Debugf("Could not find attribute %s", attributeName)
		return ""
	}
	return attr.Value
}

func XMLGetNodeValue(xmlString string, path string) string {
	if _, ok := pathCache[path]; !ok {
		compiledPath, err := etree.CompilePath(path)
		if err != nil {
			log.Errorf("Could not compile path %s: %s", path, err)
			return ""
		}
		pathCache[path] = compiledPath
	}

	compiledPath := pathCache[path]
	doc := etree.NewDocument()
	err := doc.ReadFromString(xmlString)
	if err != nil {
		log.Tracef("Could not parse XML: %s", err)
		return ""
	}
	elem := doc.FindElementPath(compiledPath)
	if elem == nil {
		log.Debugf("Could not find element %s", path)
		return ""
	}
	return elem.Text()
}
