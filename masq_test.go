package beyond

import (
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/presbrey/beyond/internal/authz"
	"github.com/stretchr/testify/assert"
)

func init() {
	// Setup file transport for HTTP client
	t := &http.Transport{}
	t.RegisterProtocol("file", http.NewFileTransport(http.Dir("/")))
	client := &http.Client{Transport: t}
	authz.SetHTTPClient(client)
}

func TestHostsCSV(t *testing.T) {
	// Reset the map for clean testing
	authz.SetHostsMap(map[string]string{})

	assert.NoError(t, authz.HostsSetup(""))
	assert.Equal(t, "test1.com", authz.RewriteHost("test1.com"))

	assert.NoError(t, authz.HostsSetup("test1.com=test1.net,test2.com=test2.org"))
	assert.Equal(t, "test1.net", authz.RewriteHost("test1.com"))
	assert.Equal(t, "test2.org", authz.RewriteHost("test2.com"))

	assert.Contains(t, authz.HostsSetup("foo").Error(), "missing equals assignment")
}

func TestHostsURL(t *testing.T) {
	// Reset the map for clean testing
	authz.SetHostsMap(map[string]string{})

	// Test with no URL
	*authz.HostsURL = ""
	assert.NoError(t, authz.RefreshHosts())
	assert.Equal(t, "old-api.example.com", authz.RewriteHost("old-api.example.com"))

	// Test with example JSON file
	cwd, _ := os.Getwd()
	*authz.HostsURL = "file://" + cwd + "/example/hosts.json"
	assert.NoError(t, authz.RefreshHosts())
	assert.Equal(t, "new-api.example.com", authz.RewriteHost("old-api.example.com"))
	assert.Equal(t, "modern.mycompany.net", authz.RewriteHost("legacy.mycompany.net"))
	assert.Equal(t, "internal.corp.example.com", authz.RewriteHost("internal.corp"))

	// Test error handling with invalid URL
	*authz.HostsURL = "file://" + cwd + "/nonexistent.json"
	assert.Error(t, authz.RefreshHosts())

	// Reset for other tests
	*authz.HostsURL = ""
	authz.SetHostsMap(map[string]string{})
}

func TestHostsOnly(t *testing.T) {
	// Reset the map and flags for clean testing
	authz.SetHostsMap(map[string]string{})
	prevHostsOnly := *authz.HostsOnly

	// Test when hosts-only is false (default)
	*authz.HostsOnly = false
	assert.True(t, authz.HostAllowed("any-host.com"))
	assert.True(t, authz.HostAllowed("random.example.com"))

	// Set up some host mappings
	assert.NoError(t, authz.HostsSetup("old-api.example.com=new-api.example.com,legacy.corp=modern.corp"))

	// Test when hosts-only is false - all hosts should be allowed
	*authz.HostsOnly = false
	assert.True(t, authz.HostAllowed("old-api.example.com"))
	assert.True(t, authz.HostAllowed("legacy.corp"))
	assert.True(t, authz.HostAllowed("unmapped-host.com"))

	// Test when hosts-only is true - only mapped hosts should be allowed
	*authz.HostsOnly = true
	assert.True(t, authz.HostAllowed("old-api.example.com"))
	assert.True(t, authz.HostAllowed("legacy.corp"))
	assert.True(t, authz.HostAllowed("subdomain.old-api.example.com")) // suffix match
	assert.False(t, authz.HostAllowed("unmapped-host.com"))
	assert.False(t, authz.HostAllowed("random.example.com"))

	// Test when hosts-only is true but no mappings exist
	authz.SetHostsMap(map[string]string{})
	*authz.HostsOnly = true
	assert.False(t, authz.HostAllowed("any-host.com"))

	// Restore original state
	*authz.HostsOnly = prevHostsOnly
	authz.SetHostsMap(map[string]string{})
}

func TestHostRewriteDetailed(t *testing.T) {
	// Reset the map for clean testing
	authz.SetHostsMap(map[string]string{})

	// Test basic host rewriting (backward compatibility)
	assert.NoError(t, authz.HostsSetup("old-api.example.com=new-api.example.com"))

	result := authz.HostRewriteDetailed("old-api.example.com")
	assert.Equal(t, "new-api.example.com", result.Host)
	assert.Equal(t, "", result.Scheme)
	assert.Equal(t, "", result.Port)
	assert.Equal(t, "", result.FullURL)

	// Test URL with protocol
	authz.SetHostsMap(map[string]string{})
	assert.NoError(t, authz.HostsSetup("legacy.corp=https://modern.corp.example.com"))

	result = authz.HostRewriteDetailed("legacy.corp")
	assert.Equal(t, "modern.corp.example.com", result.Host)
	assert.Equal(t, "https", result.Scheme)
	assert.Equal(t, "", result.Port)
	assert.Equal(t, "https://modern.corp.example.com", result.FullURL)

	// Test URL with protocol and port
	authz.SetHostsMap(map[string]string{})
	assert.NoError(t, authz.HostsSetup("internal.api=http://new-internal.api:8080"))

	result = authz.HostRewriteDetailed("internal.api")
	assert.Equal(t, "new-internal.api", result.Host)
	assert.Equal(t, "http", result.Scheme)
	assert.Equal(t, "8080", result.Port)
	assert.Equal(t, "http://new-internal.api:8080", result.FullURL)

	// Test HTTPS with non-standard port
	authz.SetHostsMap(map[string]string{})
	assert.NoError(t, authz.HostsSetup("secure.app=https://new-secure.app:9443"))

	result = authz.HostRewriteDetailed("secure.app")
	assert.Equal(t, "new-secure.app", result.Host)
	assert.Equal(t, "https", result.Scheme)
	assert.Equal(t, "9443", result.Port)
	assert.Equal(t, "https://new-secure.app:9443", result.FullURL)

	// Test subdomain matching with URL replacement
	authz.SetHostsMap(map[string]string{})
	assert.NoError(t, authz.HostsSetup("api.legacy.com=https://api.modern.com:8443"))

	result = authz.HostRewriteDetailed("service.api.legacy.com")
	assert.Equal(t, "service.api.modern.com", result.Host)
	assert.Equal(t, "https", result.Scheme)
	assert.Equal(t, "8443", result.Port)
	assert.Equal(t, "https://service.api.modern.com:8443", result.FullURL)

	// Test with no matching host
	result = authz.HostRewriteDetailed("unmatched.example.com")
	assert.Equal(t, "unmatched.example.com", result.Host)
	assert.Equal(t, "", result.Scheme)
	assert.Equal(t, "", result.Port)
	assert.Equal(t, "", result.FullURL)

	// Reset for other tests
	authz.SetHostsMap(map[string]string{})
}

func TestBackwardCompatibility(t *testing.T) {
	// Reset the map for clean testing
	authz.SetHostsMap(map[string]string{})

	// Test that RewriteHost still works the same way for simple host mappings
	assert.NoError(t, authz.HostsSetup("old.example.com=new.example.com"))
	assert.Equal(t, "new.example.com", authz.RewriteHost("old.example.com"))

	// Test that RewriteHost returns just the host part for URL mappings
	authz.SetHostsMap(map[string]string{})
	assert.NoError(t, authz.HostsSetup("old.example.com=https://new.example.com:8080"))
	assert.Equal(t, "new.example.com", authz.RewriteHost("old.example.com"))

	// Reset for other tests
	authz.SetHostsMap(map[string]string{})
}

func TestProxyIntegration(t *testing.T) {
	// Reset the map for clean testing
	authz.SetHostsMap(map[string]string{})

	// Test WebSocket URL conversion
	assert.NoError(t, authz.HostsSetup("ws.example.com=https://ws.backend.com:8443"))

	// Create a mock request
	req := &http.Request{Host: "ws.example.com"}
	req.URL, _ = url.Parse("/socket")

	wsURL, err := http2ws(req)
	assert.NoError(t, err)
	assert.Equal(t, "wss://ws.backend.com:8443/socket", wsURL.String())

	// Test HTTP backend URL conversion
	assert.NoError(t, authz.HostsSetup("api.example.com=http://api.backend.com:8080"))

	rewrite := authz.HostRewriteDetailed("api.example.com")
	assert.Equal(t, "api.backend.com", rewrite.Host)
	assert.Equal(t, "http", rewrite.Scheme)
	assert.Equal(t, "8080", rewrite.Port)
	assert.Equal(t, "http://api.backend.com:8080", rewrite.FullURL)

	// Reset for other tests
	authz.SetHostsMap(map[string]string{})
}
