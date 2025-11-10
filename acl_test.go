package beyond

import (
	"net/http"
	"os"
	"testing"

	"github.com/presbrey/beyond/internal/authz"
	"github.com/stretchr/testify/assert"
)

func init() {
	t := &http.Transport{}
	t.RegisterProtocol("file", http.NewFileTransport(http.Dir("/")))
	client := &http.Client{Transport: t}
	authz.SetHTTPClient(client)
}

const (
	aclErrorBase = "http://localhost:9999"
)

func TestACL(t *testing.T) {
	*authz.FenceURL = ""
	*authz.SitesURL = ""
	*authz.AllowlistURL = ""

	assert.NoError(t, authz.RefreshFence())
	assert.NoError(t, authz.RefreshSites())
	assert.NoError(t, authz.RefreshAllowlist())

	*authz.FenceURL = aclErrorBase
	*authz.SitesURL = aclErrorBase
	*authz.AllowlistURL = aclErrorBase

	assert.Contains(t, authz.RefreshFence().Error(), "connection refused")
	assert.Contains(t, authz.RefreshSites().Error(), "connection refused")
	assert.Contains(t, authz.RefreshAllowlist().Error(), "connection refused")

	cwd, _ := os.Getwd()
	*authz.FenceURL = "file://" + cwd + "/example/error.json"
	*authz.SitesURL = "file://" + cwd + "/example/error.json"
	*authz.AllowlistURL = "file://" + cwd + "/example/error.json"
	assert.EqualError(t, authz.RefreshFence(), "unexpected EOF")
	assert.EqualError(t, authz.RefreshSites(), "unexpected EOF")
	assert.EqualError(t, authz.RefreshAllowlist(), "unexpected EOF")

	*authz.FenceURL = "file://" + cwd + "/example/fence.json"
	*authz.SitesURL = "file://" + cwd + "/example/sites.json"
	*authz.AllowlistURL = "file://" + cwd + "/example/allowlist.json"
	assert.NoError(t, Setup())

	// Test Deny function
	reqDeny, _ := http.NewRequest("GET", "https://deny", nil)
	assert.True(t, authz.Deny(reqDeny, "consultant@gmail.com"))
	reqAllow, _ := http.NewRequest("GET", "https://github.com/test", nil)
	assert.False(t, authz.Deny(reqAllow, "consultant@gmail.com"))
}
