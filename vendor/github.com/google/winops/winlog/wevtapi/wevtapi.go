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

//go:build generate || windows
// +build generate windows

// Windows Event Log API
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa385785(v=vs.85).aspx

// Package wevtapi includes documented Windows Event Log constants, enumerations,
// functions, structures.
package wevtapi

import (
	"syscall"
)

type EvtChannelConfigPropertyID uint32

// Windows Event Log Enumerations
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa385783(v=vs.85).aspx
const (
	// EVT_CHANNEL_CONFIG_PROPERTY_ID
	EvtChannelConfigEnabled EvtChannelConfigPropertyID = iota
	EvtChannelConfigIsolation
	EvtChannelConfigType
	EvtChannelConfigOwningPublisher
	EvtChannelConfigClassicEventlog
	EvtChannelConfigAccess
	EvtChannelLoggingConfigRetention
	EvtChannelLoggingConfigAutoBackup
	EvtChannelLoggingConfigMaxSize
	EvtChannelLoggingConfigLogFilePath
	EvtChannelPublishingConfigLevel
	EvtChannelPublishingConfigKeywords
	EvtChannelPublishingConfigControlGuid
	EvtChannelPublishingConfigBufferSize
	EvtChannelPublishingConfigMinBuffers
	EvtChannelPublishingConfigMaxBuffers
	EvtChannelPublishingConfigLatency
	EvtChannelPublishingConfigClockType
	EvtChannelPublishingConfigSidType
	EvtChannelPublisherList
	EvtChannelPublishingConfigFileMax
	EvtChannelConfigPropertyIdEND

	// EVT_FORMAT_MESSAGE_FLAGS
	EvtFormatMessageEvent    = 1
	EvtFormatMessageLevel    = 2
	EvtFormatMessageTask     = 3
	EvtFormatMessageOpcode   = 4
	EvtFormatMessageKeyword  = 5
	EvtFormatMessageChannel  = 6
	EvtFormatMessageProvider = 7
	EvtFormatMessageId       = 8
	EvtFormatMessageXml      = 9

	// EVT_OPEN_LOG_FLAGS
	EvtOpenChannelPath = 1
	EvtOpenFilePath    = 2

	// EVT_RENDER_FLAGS
	EvtRenderEventValues = 0
	EvtRenderEventXml    = 1
	EvtRenderBookmark    = 2

	// EVT_QUERY_FLAGS
	EvtQueryChannelPath         = 0x1
	EvtQueryFilePath            = 0x2
	EvtQueryForwardDirection    = 0x100
	EvtQueryReverseDirection    = 0x200
	EvtQueryTolerateQueryErrors = 0x1000

	// EVT_SEEK_FLAGS
	EvtSeekRelativeToFirst    = 1
	EvtSeekRelativeToLast     = 2
	EvtSeekRelativeToCurrent  = 3
	EvtSeekRelativeToBookmark = 4
	EvtSeekOriginMask         = 7
	EvtSeekStrict             = 0x10000

	// EVT_SUBSCRIBE_FLAGS
	EvtSubscribeToFutureEvents      = 1
	EvtSubscribeStartAtOldestRecord = 2
	EvtSubscribeStartAfterBookmark  = 3
	EvtSubscribeOriginMask          = 0x3
	EvtSubscribeTolerateQueryErrors = 0x1000
	EvtSubscribeStrict              = 0x10000

	// EVT_SUBSCRIBE_NOTIFY_ACTION
	EvtSubscribeActionError   = 0
	EvtSubscribeActionDeliver = 1
)

// Windows Event Log Constants
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa385781(v=vs.85).aspx
const (
	EVT_VARIANT_TYPE_MASK  = 0x7f
	EVT_VARIANT_TYPE_ARRAY = 128
	EVT_READ_ACCESS        = 0x1
	EVT_WRITE_ACCESS       = 0x2
	EVT_CLEAR_ACCESS       = 0x3
	EVT_ALL_ACCESS         = 0x4
)

// Windows Event Log Error Constants
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa820708(v=vs.85).aspx
const (
	ERROR_EVT_INVALID_CHANNEL_PATH                          syscall.Errno = 15000
	ERROR_EVT_INVALID_QUERY                                 syscall.Errno = 15001
	ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND                  syscall.Errno = 15002
	ERROR_EVT_EVENT_TEMPLATE_NOT_FOUND                      syscall.Errno = 15003
	ERROR_EVT_INVALID_PUBLISHER_NAME                        syscall.Errno = 15004
	ERROR_EVT_INVALID_EVENT_DATA                            syscall.Errno = 15005
	ERROR_EVT_CHANNEL_NOT_FOUND                             syscall.Errno = 15007
	ERROR_EVT_MALFORMED_XML_TEXT                            syscall.Errno = 15008
	ERROR_EVT_SUBSCRIPTION_TO_DIRECT_CHANNEL                syscall.Errno = 15009
	ERROR_EVT_CONFIGURATION_ERROR                           syscall.Errno = 15010
	ERROR_EVT_QUERY_RESULT_STALE                            syscall.Errno = 15011
	ERROR_EVT_QUERY_RESULT_INVALID_POSITION                 syscall.Errno = 15012
	ERROR_EVT_NON_VALIDATING_MSXML                          syscall.Errno = 15013
	ERROR_EVT_FILTER_ALREADYSCOPED                          syscall.Errno = 15014
	ERROR_EVT_FILTER_NOTELTSET                              syscall.Errno = 15015
	ERROR_EVT_FILTER_INVARG                                 syscall.Errno = 15016
	ERROR_EVT_FILTER_INVTEST                                syscall.Errno = 15017
	ERROR_EVT_FILTER_INVTYPE                                syscall.Errno = 15018
	ERROR_EVT_FILTER_PARSEERR                               syscall.Errno = 15019
	ERROR_EVT_FILTER_UNSUPPORTEDOP                          syscall.Errno = 15020
	ERROR_EVT_FILTER_UNEXPECTEDTOKEN                        syscall.Errno = 15021
	ERROR_EVT_INVALID_OPERATION_OVER_ENABLED_DIRECT_CHANNEL syscall.Errno = 15022
	ERROR_EVT_INVALID_CHANNEL_PROPERTY_VALUE                syscall.Errno = 15023
	ERROR_EVT_INVALID_PUBLISHER_PROPERTY_VALUE              syscall.Errno = 15024
	ERROR_EVT_CHANNEL_CANNOT_ACTIVATE                       syscall.Errno = 15025
	ERROR_EVT_FILTER_TOO_COMPLEX                            syscall.Errno = 15026
	ERROR_EVT_MESSAGE_NOT_FOUND                             syscall.Errno = 15027
	ERROR_EVT_MESSAGE_ID_NOT_FOUND                          syscall.Errno = 15028
	ERROR_EVT_UNRESOLVED_VALUE_INSERT                       syscall.Errno = 15029
	ERROR_EVT_UNRESOLVED_PARAMETER_INSERT                   syscall.Errno = 15030
	ERROR_EVT_MAX_INSERTS_REACHED                           syscall.Errno = 15031
	ERROR_EVT_EVENT_DEFINITION_NOT_FOUND                    syscall.Errno = 15032
	ERROR_EVT_MESSAGE_LOCALE_NOT_FOUND                      syscall.Errno = 15033
	ERROR_EVT_VERSION_TOO_OLD                               syscall.Errno = 15034
	ERROR_EVT_VERSION_TOO_NEW                               syscall.Errno = 15035
	ERROR_EVT_CANNOT_OPEN_CHANNEL_OF_QUERY                  syscall.Errno = 15036
	ERROR_EVT_PUBLISHER_DISABLED                            syscall.Errno = 15037
	ERROR_EVT_FILTER_OUT_OF_RANGE                           syscall.Errno = 15038
)

// Windows Event Log Functions
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa385784(v=vs.85).aspx

// These comments are used with the go generate command combined with the mksyscall
// library to generate Windows syscalls. The generated file is not to be modified and may raise some lint warnings.
// See: https://golang.org/src/syscall/mksyscall_windows.go

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zwevtapi.go wevtapi.go
//sys   EvtClearLog(session windows.Handle, channelPath *uint16, targetFilePath *uint16, flags uint32) (err error) = wevtapi.EvtClearLog
//sys   EvtClose(event windows.Handle) (err error) = wevtapi.EvtClose
//sys   EvtCreateBookmark(bookmarkXML *uint16) (handle windows.Handle, err error) = wevtapi.EvtCreateBookmark
//sys	  EvtCreateRenderContext(valuePathsCount uint32, valuePaths uintptr, flags uint32) (handle windows.Handle, err error) = wevtapi.EvtCreateRenderContext
//sys   EvtExportLog(session windows.Handle, path *uint16, query *uint16, targetFilePath *uint16, flags uint32) (err error) = wevtapi.EvtExportLog
//sys   EvtFormatMessage(pubMetaData windows.Handle, event windows.Handle, messageID uint32, valueCount uint32, variant uintptr, flags uint32, bufferSize uint32, buffer *byte, bufferUsed *uint32) (err error) = wevtapi.EvtFormatMessage
//sys   EvtGetChannelConfigProperty(channelConfig windows.Handle, propertyID EvtChannelConfigPropertyID, flags uint32, bufferSize uint32, buffer unsafe.Pointer, bufferUsed *uint32) (err error) = wevtapi.EvtGetChannelConfigProperty
//sys   EvtNext(resultSet windows.Handle, eventArraySize uint32, eventArray *windows.Handle, timeout uint32, flags uint32, returned *uint32) (err error) = wevtapi.EvtNext
//sys   EvtNextChannelPath(channelEnum windows.Handle, channelPathBufferSize uint32, channelPathBuffer *uint16, channelPathBufferUsed *uint32) (err error) = wevtapi.EvtNextChannelPath
//sys   EvtNextPublisherId(publisherEnum windows.Handle, publisherIDBufferSize uint32, publisherIDBuffer *uint16, publisherIDBufferUsed *uint32) (err error) = wevtapi.EvtNextPublisherId
//sys   EvtOpenChannelConfig(event windows.Handle, channelPath *uint16, flags uint32) (handle windows.Handle, err error) = wevtapi.EvtOpenChannelConfig
//sys   EvtOpenChannelEnum(session windows.Handle, flags uint32) (handle windows.Handle, err error) = wevtapi.EvtOpenChannelEnum
//sys   EvtOpenLog(session windows.Handle, path *uint16, flags uint32) (handle windows.Handle, err error) = wevtapi.EvtOpenLog
//sys   EvtOpenPublisherEnum(session windows.Handle, flags uint32) (handle windows.Handle, err error) = wevtapi.EvtOpenPublisherEnum
//sys   EvtOpenPublisherMetadata(session windows.Handle, publisherIdentity *uint16, logFilePath *uint16, locale uint32, flags uint32) (handle windows.Handle, err error) = wevtapi.EvtOpenPublisherMetadata
//sys   EvtOpenSession(loginClass uint32, login uintptr, timeout uint32, flags uint32) (handle windows.Handle, err error) = wevtapi.EvtOpenSession
//sys   EvtQuery(session windows.Handle, path *uint16, query *uint16, flags uint32) (handle windows.Handle, err error) = wevtapi.EvtQuery
//sys   EvtRender(ctx windows.Handle, fragment windows.Handle, flags uint32, bufferSize uint32, buffer unsafe.Pointer, bufferUsed *uint32, propertyCount *uint32) (err error) = wevtapi.EvtRender
//sys   EvtSeek(resultSet windows.Handle, position int64, bookmark windows.Handle, timeout uint32, flags uint32) (err error) = wevtapi.EvtSeek
//sys   EvtSubscribe(session windows.Handle, signalEvent windows.Handle, channelPath *uint16, query *uint16, bookmark windows.Handle, ctx uintptr, callback uintptr, flags uint32) (handle windows.Handle, err error) = wevtapi.EvtSubscribe
//sys   EvtUpdateBookmark(bookmark windows.Handle, event windows.Handle) (err error) = wevtapi.EvtUpdateBookmark
