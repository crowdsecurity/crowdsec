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

var (
	pathCache        = make(map[string]etree.Path)
	rwMutex          = sync.RWMutex{}
	xmlDocumentCache gcache.Cache
)

func compileOrGetPath(path string) (etree.Path, error) {
	rwMutex.RLock()
	compiledPath, ok := pathCache[path]
	rwMutex.RUnlock()

	if !ok {
		var err error
		compiledPath, err = etree.CompilePath(path)
		if err != nil {
			return etree.Path{}, err
		}

		rwMutex.Lock()
		pathCache[path] = compiledPath
		rwMutex.Unlock()
	}

	return compiledPath, nil
}

func getXMLDocumentFromCache(xmlString string) (*etree.Document, error) {
	cacheKey := xxhash.Sum64String(xmlString)
	cacheObj, err := xmlDocumentCache.Get(cacheKey)

	if err != nil && !errors.Is(err, gcache.KeyNotFoundError) {
		return nil, err
	}

	doc, ok := cacheObj.(*etree.Document)
	if !ok || cacheObj == nil {
		doc = etree.NewDocument()
		if err := doc.ReadFromString(xmlString); err != nil {
			return nil, err
		}
		if err := xmlDocumentCache.Set(cacheKey, doc); err != nil {
			log.Warnf("Could not set XML document in cache: %s", err)
		}
	}

	return doc, nil
}

func XMLCacheInit() {
	gc := gcache.New(50)
	// 	Short cache expiration because we each line we read is different, but we can call multiple times XML helpers on each of them
	gc.Expiration(5 * time.Second)
	gc = gc.LRU()

	xmlDocumentCache = gc.Build()
}

// func XMLGetAttributeValue(xmlString string, path string, attributeName string) string {
func XMLGetAttributeValue(params ...any) (any, error) {
	xmlString := params[0].(string)
	path := params[1].(string)
	attributeName := params[2].(string)

	compiledPath, err := compileOrGetPath(path)
	if err != nil {
		log.Errorf("Could not compile path %s: %s", path, err)
		return "", nil
	}

	doc, err := getXMLDocumentFromCache(xmlString)
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
	xmlString := params[0].(string)
	path := params[1].(string)

	compiledPath, err := compileOrGetPath(path)
	if err != nil {
		log.Errorf("Could not compile path %s: %s", path, err)
		return "", nil
	}

	doc, err := getXMLDocumentFromCache(xmlString)
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
