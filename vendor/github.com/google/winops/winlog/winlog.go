// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build windows
// +build windows

// Package winlog provides convenience functions for using the Windows Event Log API.
package winlog

import (
	"fmt"
	"regexp"
	"syscall"
	"time"
	"unsafe"

	"github.com/golang/glog"
	"golang.org/x/sys/windows"
	"github.com/google/winops/winlog/wevtapi"
)

// Windows function parameters.
const (
	localMachine = 0 // Identifies the local machine for Windows API functions.
	mustBeZero   = 0 // For reserved Windows API function parameters.
)

// SubscribeConfig describes parameters for initializing a Windows Event Log subscription.
type SubscribeConfig struct {
	Session     windows.Handle
	SignalEvent windows.Handle
	ChannelPath *uint16
	Query       *uint16
	Bookmark    windows.Handle
	Context     uintptr
	Callback    uintptr
	Flags       uint32
}

// Close closes a Windows event log handle.
func Close(h windows.Handle) error {
	if h == windows.InvalidHandle {
		// InvalidHandle is used to cache the "File not found" result
		// from OpenPublisherMetadata.
		return nil
	}

	return wevtapi.EvtClose(h)
}

// DefaultSubscribeConfig creates a default subscriber configuration to be used
// to initialize a pull subscription for the classic Windows Event Log channels.
func DefaultSubscribeConfig() (*SubscribeConfig, error) {
	var config SubscribeConfig
	var err error

	// Create a subscription signaler.
	config.SignalEvent, err = windows.CreateEvent(
		nil, // Default security descriptor.
		1,   // Manual reset.
		1,   // Initial state is signaled.
		nil) // Optional name.
	if err != nil {
		return &config, fmt.Errorf("windows.CreateEvent failed: %v", err)
	}

	// Build a structured XML query retrieving all the events from the classic
	// Windows Event Log channels and start the subscription from the oldest record.
	config.Flags = wevtapi.EvtSubscribeStartAtOldestRecord
	xpaths := map[string]string{"Application": "*", "Security": "*", "System": "*"}
	xmlQuery, err := BuildStructuredXMLQuery(xpaths)
	if err != nil {
		return nil, fmt.Errorf("BuildStructuredXMLQuery failed: %v", err)
	}
	config.Query, err = syscall.UTF16PtrFromString(string(xmlQuery))
	if err != nil {
		return &config, fmt.Errorf("syscall.UTF16PtrFromString failed: %v", err)
	}

	return &config, nil
}

// GetRenderedEvents iterates over a subscription or query result set up to a configurable
// maximum and returns the rendered events as a slice of UTF8 formatted XML strings.
// publisherCache is a cache of Handles for publisher metadata to avoid
// expensive Windows API calls. Pass in an empty map on the first call. Once
// you've finished using GetRenderedEvents, pass all the contained values to Close.
func GetRenderedEvents(config *SubscribeConfig, publisherCache map[string]windows.Handle, resultSet windows.Handle, maxEvents int, locale uint32) ([]string, error) {
	var events = make([]windows.Handle, maxEvents)
	var returned uint32

	// Get handles to events from the result set.
	err := wevtapi.EvtNext(
		resultSet,           // Handle to query or subscription result set.
		uint32(len(events)), // The number of events to attempt to retrieve.
		&events[0],          // Pointer to the array of event handles.
		2000,                // Timeout in milliseconds to wait.
		0,                   // Reserved. Must be zero.
		&returned)           // The number of handles in the array that are set by the API.
	if err == windows.ERROR_NO_MORE_ITEMS {
		return nil, err
	} else if err != nil {
		return nil, fmt.Errorf("wevtapi.EvtNext failed: %v", err)
	}

	// Event handles must be closed after they are returned by EvtNext whether or not we use them.
	defer func() {
		for _, event := range events[:returned] {
			Close(event)
		}
	}()

	// Render events.
	var renderedEvents []string
	for _, event := range events[:returned] {
		// Render the basic XML representation of the event.
		fragment, err := RenderFragment(event, wevtapi.EvtRenderEventXml)
		if err != nil {
			glog.Errorf("Failed to render event with EvtRenderEventXml, skipping: %v", err)
			continue
		}

		// Attempt to render the full event using the basic event.
		renderedEvent, err := RenderFormattedMessageXML(event, fragment, locale, publisherCache)
		if err != nil {
			glog.Errorf("Failed to fully render event, returning fragment: %v\n%v", err, fragment)
			renderedEvent = fragment
		}
		renderedEvents = append(renderedEvents, renderedEvent)
	}

	// If a bookmark is used in the configuration, update it.
	if config.Bookmark != 0 {
		err = wevtapi.EvtUpdateBookmark(config.Bookmark, events[returned-1])
		if err != nil {
			return nil, fmt.Errorf("wevtapi.EvtUpdateBookmark failed: %v", err)
		}
	}

	return renderedEvents, err
}

// RenderFragment renders a Windows Event Log fragment according to the specified flag.
// Supports rendering events and bookmarks as UTF8 formatted XML strings.
func RenderFragment(fragment windows.Handle, flag uint32) (string, error) {
	var bufferUsed uint32
	var propertyCount uint32

	// Call EvtRender with a null buffer to get the required buffer size.
	err := wevtapi.EvtRender(
		0,
		fragment,
		flag,
		0,
		nil,
		&bufferUsed,
		&propertyCount)
	if err != syscall.ERROR_INSUFFICIENT_BUFFER {
		return "", fmt.Errorf("wevtapi.EvtRender failed: %v", err)
	}

	// Create a buffer based on the buffer size required.
	buf := make([]uint16, bufferUsed/2)

	// Render the fragment according to the flag.
	err = wevtapi.EvtRender(
		0,
		fragment,
		flag,
		bufferUsed,
		unsafe.Pointer(&buf[0]),
		&bufferUsed,
		&propertyCount)
	if err != nil {
		return "", fmt.Errorf("wevtapi.EvtRender failed: %v", err)
	}

	return syscall.UTF16ToString(buf), nil
}

// RenderFormattedMessageXML renders a Windows Event Log event as a UTF8 formatted XML string.
// This includes the RenderingInfo node parsed by leveraging the event publisher and desired
// locale (LCID). Returns the original raw XML if a publisher for the event is unavailable.
func RenderFormattedMessageXML(event windows.Handle, renderedEvent string, locale uint32, cache map[string]windows.Handle) (string, error) {
	// Find the event publisher using the raw event XML.
	re := regexp.MustCompile(`Provider Name='(.*?)\'`)
	publisherMatch := re.FindStringSubmatch(renderedEvent)
	if len(publisherMatch) < 2 {
		return "", fmt.Errorf("RenderFormattedMessageXML: no publisher name found in event")
	}
	publisherName := publisherMatch[1]

	// Lookup publisher metadata.
	var pubHandle windows.Handle
	if val, ok := cache[publisherName]; ok {
		if val == windows.InvalidHandle {
			// We already got ERROR_FILE_NOT_FOUND for this publisher.
			return renderedEvent, nil
		}
		pubHandle = val
	} else {
		glog.V(1).Infof("Calling OpenPublisherMetadata(%q)...", publisherName)
		start := time.Now()
		defer func() {
			glog.V(1).Infof("OpenPublisherMetadata(%q) returned after %v", publisherName, time.Since(start))
		}()

		var err error
		pubHandle, err = OpenPublisherMetadata(localMachine, publisherName, locale)
		// If there is no publisher metadata available return the original event.
		if err == syscall.ERROR_FILE_NOT_FOUND {
			cache[publisherName] = windows.InvalidHandle
			return renderedEvent, nil
		} else if err != nil {
			return "", fmt.Errorf("OpenPublisherMetadata failed: %v", err)
		}
		cache[publisherName] = pubHandle
	}

	// Call EvtFormatMessage with a null buffer to get the required buffer size.
	var bufferUsed uint32
	err := wevtapi.EvtFormatMessage(
		pubHandle,                   // Handle to provider metadata.
		event,                       // Handle to an event.
		0,                           // Resource identifier of the message string. Null if flag isn't EvtFormatMessageId.
		0,                           // Number of values in the values parameter.
		0,                           // An array of insertion values to be used when formatting the event string. Typically set to null.
		wevtapi.EvtFormatMessageXml, // Format message as an XML string.
		0,                           // Size of buffer.
		nil,                         // Null buffer.
		&bufferUsed)                 // Get the required buffer size.
	if err != syscall.ERROR_INSUFFICIENT_BUFFER {
		return "", fmt.Errorf("wevtapi.EvtFormatMessage failed to get buffer size: %v", err)
	}

	buf := make([]uint16, bufferUsed)

	// Render the event as a formatted XML string with RenderingInfo node.
	err = wevtapi.EvtFormatMessage(pubHandle, event, 0, 0, 0, wevtapi.EvtFormatMessageXml,
		bufferUsed, (*byte)(unsafe.Pointer(&buf[0])), &bufferUsed)
	if err == windows.ERROR_EVT_MESSAGE_ID_NOT_FOUND {
		// Workaround for Windows 11 (b/202285931)
		return renderedEvent, nil
	} else if err != nil {
		return "", fmt.Errorf("wevtapi.EvtFormatMessage failed to render events as formatted XML: %v", err)
	}

	return syscall.UTF16ToString(buf), nil
}

// Subscribe initializes a subscription and returns a handle to the subscription.
// Close must be called on the returned handle when finished.
func Subscribe(config *SubscribeConfig) (windows.Handle, error) {
	// Initialize the subscription.
	subscription, err := wevtapi.EvtSubscribe(
		config.Session,
		config.SignalEvent,
		config.ChannelPath,
		config.Query,
		config.Bookmark,
		config.Context,
		config.Callback,
		config.Flags)
	if err != nil {
		return 0, fmt.Errorf("wevtapi.EvtSubscribe(): %w", err)
	}

	return subscription, nil
}

// Close closes the subscribe config. Note that the subscribe config
// needs to outlive the subscription. Close returns one of the
// encountered errors, but it still attempts to close everything
// that's needed.
func (cfg *SubscribeConfig) Close() (closeErr error) {
	if cfg.Bookmark != 0 {
		if err := wevtapi.EvtClose(cfg.Bookmark); err != nil {
			closeErr = fmt.Errorf("wevtapi.EvtClose(cfg.Bookmark): %w", err)
		} else { // success
			cfg.Bookmark = 0
		}
	}
	if cfg.Session != 0 {
		if err := windows.CloseHandle(cfg.Session); err != nil {
			closeErr = fmt.Errorf("windows.CloseHandle(cfg.Session): %w", err)
		} else { // success
			cfg.Session = 0
		}
	}
	if cfg.SignalEvent != 0 {
		if err := windows.CloseHandle(cfg.SignalEvent); err != nil {
			closeErr = fmt.Errorf("windows.CloseHandle(cfg.SignalEvent): %w", err)
		} else { // success
			cfg.SignalEvent = 0
		}
	}
	return closeErr
}
