package exprhelpers

import (
	"errors"
	"sync"
	"time"

	"github.com/beevik/etree"
	"github.com/bluele/gcache"
	"github.com/cespare/xxhash/v2"
	log "github.com/sirupsen/logrus"
)

var pathCache = make(map[string]etree.Path)
var rwMutex = sync.RWMutex{}
var xmlDocumentCache gcache.Cache

func XMLCacheInit() error {
	gc := gcache.New(50)
	// 	Short cache expiration because we each line we read is different, but we can call multiple times XML helpers on each of them
	gc.Expiration(5 * time.Second)
	gc = gc.LRU()

	xmlDocumentCache = gc.Build()
	return nil
}

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

	cacheKey := xxhash.Sum64String(xmlString)

	cacheObj, err := xmlDocumentCache.Get(cacheKey)

	if err != nil && !errors.Is(err, gcache.KeyNotFoundError) {
		log.Errorf("Could not get XML document from cache: %s", err)
		return "", nil
	}

	var doc *etree.Document

	doc, ok = cacheObj.(*etree.Document)

	if cacheObj == nil || !ok {
		doc = etree.NewDocument()
		err = doc.ReadFromString(xmlString)
		if err != nil {
			log.Tracef("Could not parse XML: %s", err)
			return "", nil
		}
		err = xmlDocumentCache.Set(cacheKey, doc)

		if err != nil {
			log.Warnf("Could not set XML document in cache: %s", err)
		}
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

	cacheKey := xxhash.Sum64String(xmlString)

	cacheObj, err := xmlDocumentCache.Get(cacheKey)

	if err != nil && !errors.Is(err, gcache.KeyNotFoundError) {
		log.Errorf("Could not get XML document from cache: %s", err)
		return "", nil
	}

	var doc *etree.Document

	doc, ok = cacheObj.(*etree.Document)

	if cacheObj == nil || !ok {
		doc = etree.NewDocument()
		err = doc.ReadFromString(xmlString)
		if err != nil {
			log.Tracef("Could not parse XML: %s", err)
			return "", nil
		}
		err = xmlDocumentCache.Set(cacheKey, doc)

		if err != nil {
			log.Warnf("Could not set XML document in cache: %s", err)
		}
	}

	elem := doc.FindElementPath(compiledPath)
	if elem == nil {
		log.Debugf("Could not find element %s", path)
		return "", nil
	}
	return elem.Text(), nil
}
