package beyond

import (
	"testing"

	"github.com/presbrey/beyond/internal/authn"
	"github.com/stretchr/testify/assert"
)

func init() {
	*authn.CookieKey = "a8b91cde2e3eb7fcd544ece2bdf3ce6d0599fbbcbb1cfc144e1c2bf3cd7a13de"
}

func TestSetupAutoGenerate(t *testing.T) {
	prev := *authn.CookieKey
	*authn.CookieKey = ""
	err := authn.SetupSession()
	assert.NoError(t, err)
	assert.Len(t, *authn.CookieKey, 64) // Should be 64 hex chars
	*authn.CookieKey = prev
}

func TestSetupBadKeyLength(t *testing.T) {
	prev := *authn.CookieKey
	*authn.CookieKey = "short"
	err := authn.SetupSession()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cookie key must be exactly 64 hex characters")
	*authn.CookieKey = prev
}

func TestSetupBadKeyFormat(t *testing.T) {
	prev := *authn.CookieKey
	*authn.CookieKey = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"
	err := authn.SetupSession()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cookie key must be valid hex")
	*authn.CookieKey = prev
}
