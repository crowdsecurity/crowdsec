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

	"github.com/google/winops/winlog/wevtapi"
)

// AvailableChannels returns a slice of channels registered on the system.
func AvailableChannels() ([]string, error) {
	h, err := wevtapi.EvtOpenChannelEnum(localMachine, mustBeZero)
	if err != nil {
		return nil, fmt.Errorf("wevtapi.EvtOpenChannelEnum failed: %v", err)
	}
	defer Close(h)

	// Enumerate all the channel names. Dynamically allocate the buffer to receive
	// channel names depending on the buffer size required as reported by the API.
	var channels []string
	buf := make([]uint16, 1)
	for {
		var bufferUsed uint32
		err := wevtapi.EvtNextChannelPath(h, uint32(len(buf)), &buf[0], &bufferUsed)
		switch err {
		case nil:
			channels = append(channels, syscall.UTF16ToString(buf[:bufferUsed]))
		case syscall.ERROR_INSUFFICIENT_BUFFER:
			// Grow buffer.
			buf = make([]uint16, bufferUsed)
			continue
		case syscall.Errno(259): // ERROR_NO_MORE_ITEMS
			return channels, nil
		default:
			return nil, fmt.Errorf("wevtapi.EvtNextChannelPath failed: %v", err)
		}
	}
}
