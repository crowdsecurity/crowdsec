package exprhelpers

import (
	"sync"

	"github.com/beevik/etree"
	log "github.com/sirupsen/logrus"
)

var pathCache = make(map[string]etree.Path)
var rwMutex = sync.RWMutex{}

// func XMLGetAttributeValue(xmlString string, path string, attributeName string) string {
func XMLGetAttributeValue(params ...any) (any, error) {
	var compiledPath etree.Path
	var err error
	var ok bool

	xmlString := params[0].(string)
	path := params[1].(string)
	attributeName := params[2].(string)
	rwMutex.RLock()
	if compiledPath, ok = pathCache[path]; !ok {
		compiledPath, err = etree.CompilePath(path)
		if err != nil {
			log.Errorf("Could not compile path %s: %s", path, err)
			rwMutex.RUnlock()
			return "", nil
		}
		rwMutex.RUnlock()
		rwMutex.Lock()
		pathCache[path] = compiledPath
		rwMutex.Unlock()
	} else {
		rwMutex.RUnlock()
	}

	doc := etree.NewDocument()
	err = doc.ReadFromString(xmlString)
	if err != nil {
		log.Tracef("Could not parse XML: %s", err)
		return "", nil
	}
	elem := doc.FindElementPath(compiledPath)
	if elem == nil {
		log.Debugf("Could not find element %s", path)
		return "", nil
	}
	attr := elem.SelectAttr(attributeName)
	if attr == nil {
		log.Debugf("Could not find attribute %s", attributeName)
		return "", nil
	}
	return attr.Value, nil
}

// func XMLGetNodeValue(xmlString string, path string) string {
func XMLGetNodeValue(params ...any) (any, error) {
	var compiledPath etree.Path
	var err error
	var ok bool

	xmlString := params[0].(string)
	path := params[1].(string)

	rwMutex.RLock()
	if compiledPath, ok = pathCache[path]; !ok {
		compiledPath, err = etree.CompilePath(path)
		if err != nil {
			log.Errorf("Could not compile path %s: %s", path, err)
			rwMutex.RUnlock()
			return "", nil
		}
		rwMutex.RUnlock()
		rwMutex.Lock()
		pathCache[path] = compiledPath
		rwMutex.Unlock()
	} else {
		rwMutex.RUnlock()
	}

	doc := etree.NewDocument()
	err = doc.ReadFromString(xmlString)
	if err != nil {
		log.Tracef("Could not parse XML: %s", err)
		return "", nil
	}
	elem := doc.FindElementPath(compiledPath)
	if elem == nil {
		log.Debugf("Could not find element %s", path)
		return "", nil
	}
	return elem.Text(), nil
}
