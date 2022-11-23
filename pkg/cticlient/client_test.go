package cticlient

import "testing"

const validApiKey = "my-api-key"

func TestSmoke(t *testing.T) {
	ctiClient := NewCrowdsecCTIClient("asdasd")
	_, err := ctiClient.GetIPInfo("8.8.8.8")
	if err != nil {
		t.Fatalf("failed to get ip info: %s", err)
	}
}
