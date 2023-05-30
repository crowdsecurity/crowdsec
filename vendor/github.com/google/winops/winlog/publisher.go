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
	"syscall"

	"golang.org/x/sys/windows"
	"github.com/google/winops/winlog/wevtapi"
)

// AvailablePublishers returns a slice of publishers registered on the system.
func AvailablePublishers() ([]string, error) {
	h, err := wevtapi.EvtOpenPublisherEnum(localMachine, mustBeZero)
	if err != nil {
		return nil, fmt.Errorf("wevtapi.EvtOpenPublisherEnum failed: %v", err)
	}
	defer Close(h)

	var publishers []string
	buf := make([]uint16, 1)
	for {
		var bufferUsed uint32
		err := wevtapi.EvtNextPublisherId(h, uint32(len(buf)), &buf[0], &bufferUsed)
		switch err {
		case nil:
			publishers = append(publishers, syscall.UTF16ToString(buf[:bufferUsed]))
		case syscall.ERROR_INSUFFICIENT_BUFFER:
			// Grow buffer.
			buf = make([]uint16, bufferUsed)
			continue
		case windows.ERROR_NO_MORE_ITEMS:
			return publishers, nil
		default:
			return nil, fmt.Errorf("wevtapi.EvtNextPublisherId failed: %v", err)
		}
	}
}

// OpenPublisherMetadata opens a handle to the publisher's metadata.
// Close must be called on the returned handle when finished.
func OpenPublisherMetadata(session windows.Handle, publisherName string, locale uint32) (windows.Handle, error) {
	pub, err := syscall.UTF16PtrFromString(publisherName)
	if err != nil {
		return 0, fmt.Errorf("syscall.UTF16PtrFromString failed: %v", err)
	}

	return wevtapi.EvtOpenPublisherMetadata(session, pub, nil, locale, mustBeZero)
}
