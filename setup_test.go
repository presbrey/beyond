package beyond

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func init() {
	*cookieKey = "a8b91cde2e3eb7fcd544ece2bdf3ce6d0599fbbcbb1cfc144e1c2bf3cd7a13de"
}

func TestSetupAutoGenerate(t *testing.T) {
	prev := *cookieKey
	*cookieKey = ""
	err := Setup()
	assert.NoError(t, err)
	assert.Len(t, *cookieKey, 64) // Should be 64 hex chars
	*cookieKey = prev
}

func TestSetupBadKeyLength(t *testing.T) {
	prev := *cookieKey
	*cookieKey = "short"
	err := Setup()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cookie key must be exactly 64 hex characters")
	*cookieKey = prev
}

func TestSetupBadKeyFormat(t *testing.T) {
	prev := *cookieKey
	*cookieKey = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"
	err := Setup()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cookie key must be valid hex")
	*cookieKey = prev
}
