package protocol

import (
	"io"
)

// RoundTrip sends a request to a kafka broker and returns the response.
func RoundTrip(rw io.ReadWriter, apiVersion int16, correlationID int32, clientID string, req Message) (Message, error) {
	if err := WriteRequest(rw, apiVersion, correlationID, clientID, req); err != nil {
		return nil, err
	}
	if !hasResponse(req) {
		return nil, nil
	}
	id, res, err := ReadResponse(rw, req.ApiKey(), apiVersion)
	if err != nil {
		return nil, err
	}
	if id != correlationID {
		return nil, Errorf("correlation id mismatch (expected=%d, found=%d)", correlationID, id)
	}
	return res, nil
}

func hasResponse(msg Message) bool {
	x, _ := msg.(interface{ HasResponse() bool })
	return x == nil || x.HasResponse()
}
