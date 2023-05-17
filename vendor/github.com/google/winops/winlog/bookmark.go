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

package winlog

import (
	"fmt"
	"log"
	"syscall"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows"
	"github.com/google/winops/winlog/wevtapi"
)

// CreateBookmark creates a bookmark that identifies an event in a channel.
// Returns a handle to the bookmark.
func CreateBookmark(b string) (windows.Handle, error) {
	// An empty bookmark string is valid for initialization or a forced reset.
	if b == "" {
		log.Println("Empty bookmark. Starting new.")
		bookmark, err := wevtapi.EvtCreateBookmark(nil)
		if err != nil {
			return 0, fmt.Errorf("wevtapi.EvtCreateBookmark failed: %v", err)
		}
		return bookmark, nil
	}
	// Create a bookmark from an existing bookmark string.
	p, err := syscall.UTF16PtrFromString(b)
	if err != nil {
		return 0, fmt.Errorf("syscall.UTF16PtrFromString failed: %v", err)
	}
	bookmark, err := wevtapi.EvtCreateBookmark(p)
	if err != nil {
		// Existing bookmark may be invalid or otherwise corrupted.
		// Attempt to recover by creating a new bookmark.
		log.Println("Bookmark may be corrupted. Starting new.")
		bookmark, err = wevtapi.EvtCreateBookmark(nil)
		if err != nil {
			return 0, fmt.Errorf("wevtapi.EvtCreateBookmark failed: %v", err)
		}
	}
	return bookmark, nil
}

// GetBookmarkRegistry reads a registry key for a bookmark string.
// Returns an error if the key does not exist.
// If no bookmark exists or is malformed, it creates one. Sets a handle
// to the bookmark to be used in a subscription or query.
func GetBookmarkRegistry(config *SubscribeConfig, regKey registry.Key, path string, value string) error {
	k, err := registry.OpenKey(regKey, path, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("registry.OpenKey failed: %v", err)
	}
	defer k.Close()

	// Read the bookmark from the registry.
	b, _, err := k.GetStringValue(value)
	if err == syscall.ERROR_FILE_NOT_FOUND {
		k.SetStringValue(value, "")
	} else if err != nil {
		return fmt.Errorf("registry.GetStringValue failed: %v", err)
	}

	// Create a bookmark from an existing bookmark string.
	config.Bookmark, err = CreateBookmark(b)
	if err != nil {
		return fmt.Errorf("CreateBookmark failed: %v", err)
	}

	return nil
}

// SetBookmarkRegistry sets a registry value representing a Windows Event Log bookmark.
func SetBookmarkRegistry(bookmark windows.Handle, regKey registry.Key, path string, value string) error {
	// Render bookmark.
	bookmarkXML, err := RenderFragment(bookmark, wevtapi.EvtRenderBookmark)
	if err != nil {
		return fmt.Errorf("RenderFragment failed: %v", err)
	}

	// Persist rendered bookmark to registry.
	k, err := registry.OpenKey(regKey, path, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("registry.OpenKey failed: %v", err)
	}
	defer k.Close()

	err = k.SetStringValue(value, bookmarkXML)
	if err != nil {
		return fmt.Errorf("registry.SetStringValue failed: %v", err)
	}

	return nil
}
