package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseFiltersAcceptsSCIONCaseInsensitive(t *testing.T) {
	previous := connectionTypeFilter
	t.Cleanup(func() { connectionTypeFilter = previous })
	connectionTypeFilter = "sCiOn"
	assert.NoError(t, parseFilters())
}

func TestParsingOfIP(t *testing.T) {
	InterfaceIP := "192.168.178.123/16"

	parsedIP := parseInterfaceIP(InterfaceIP)

	assert.Equal(t, "192.168.178.123\n", parsedIP)
}
