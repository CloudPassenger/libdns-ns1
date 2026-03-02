package main

import (
	"os"
	"strings"
	"testing"

	"github.com/CloudPassenger/libdns-ns1"
	"github.com/libdns/libdns/libdnstest"
)

func TestNS1Provider(t *testing.T) {
	apiKey := os.Getenv("NS1_API_KEY")
	testZone := os.Getenv("NS1_TEST_ZONE")

	if apiKey == "" || testZone == "" {
		t.Skip("Skipping NS1 provider tests: NS1_API_KEY and/or NS1_TEST_ZONE environment variables must be set")
	}

	if !strings.HasSuffix(testZone, ".") {
		t.Fatal("We expect the test zone to have trailing dot")
	}

	provider := &ns1.Provider{
		APIKey: apiKey,
	}

	if endpoint := os.Getenv("NS1_API_ENDPOINT"); endpoint != "" {
		provider.Endpoint = endpoint
	}

	suite := libdnstest.NewTestSuite(provider, testZone)
	suite.RunTests(t)
}
