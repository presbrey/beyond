package beyond

import (
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func init() {
	// Setup file transport for HTTP client
	t := &http.Transport{}
	t.RegisterProtocol("file", http.NewFileTransport(http.Dir("/")))
	httpACL.Transport = t
}

func TestHostsCSV(t *testing.T) {
	// Reset the map for clean testing
	hostsMap = map[string]string{}
	
	assert.NoError(t, hostsSetup(""))
	assert.Equal(t, "test1.com", hostRewrite("test1.com"))

	assert.NoError(t, hostsSetup("test1.com=test1.net,test2.com=test2.org"))
	assert.Equal(t, "test1.net", hostRewrite("test1.com"))
	assert.Equal(t, "test2.org", hostRewrite("test2.com"))

	assert.Contains(t, hostsSetup("foo").Error(), "missing equals assignment")
}

func TestHostsURL(t *testing.T) {
	// Reset the map for clean testing
	hostsMap = map[string]string{}
	
	// Test with no URL
	*hostsURL = ""
	assert.NoError(t, refreshHosts())
	assert.Equal(t, "old-api.example.com", hostRewrite("old-api.example.com"))
	
	// Test with example JSON file
	cwd, _ := os.Getwd()
	*hostsURL = "file://" + cwd + "/example/hosts.json"
	assert.NoError(t, refreshHosts())
	assert.Equal(t, "new-api.example.com", hostRewrite("old-api.example.com"))
	assert.Equal(t, "modern.mycompany.net", hostRewrite("legacy.mycompany.net"))
	assert.Equal(t, "internal.corp.example.com", hostRewrite("internal.corp"))
	
	// Test error handling with invalid URL
	*hostsURL = "file://" + cwd + "/nonexistent.json"
	assert.Error(t, refreshHosts())
	
	// Reset for other tests
	*hostsURL = ""
	hostsMap = map[string]string{}
}

func TestHostsOnly(t *testing.T) {
	// Reset the map and flags for clean testing
	hostsMap = map[string]string{}
	prevHostsOnly := *hostsOnly
	
	// Test when hosts-only is false (default)
	*hostsOnly = false
	assert.True(t, hostAllowed("any-host.com"))
	assert.True(t, hostAllowed("random.example.com"))
	
	// Set up some host mappings
	assert.NoError(t, hostsSetup("old-api.example.com=new-api.example.com,legacy.corp=modern.corp"))
	
	// Test when hosts-only is false - all hosts should be allowed
	*hostsOnly = false
	assert.True(t, hostAllowed("old-api.example.com"))
	assert.True(t, hostAllowed("legacy.corp"))
	assert.True(t, hostAllowed("unmapped-host.com"))
	
	// Test when hosts-only is true - only mapped hosts should be allowed
	*hostsOnly = true
	assert.True(t, hostAllowed("old-api.example.com"))
	assert.True(t, hostAllowed("legacy.corp"))
	assert.True(t, hostAllowed("subdomain.old-api.example.com")) // suffix match
	assert.False(t, hostAllowed("unmapped-host.com"))
	assert.False(t, hostAllowed("random.example.com"))
	
	// Test when hosts-only is true but no mappings exist
	hostsMap = map[string]string{}
	*hostsOnly = true
	assert.False(t, hostAllowed("any-host.com"))
	
	// Restore original state
	*hostsOnly = prevHostsOnly
	hostsMap = map[string]string{}
}

func TestHostRewriteDetailed(t *testing.T) {
	// Reset the map for clean testing
	hostsMap = map[string]string{}
	
	// Test basic host rewriting (backward compatibility)
	assert.NoError(t, hostsSetup("old-api.example.com=new-api.example.com"))
	
	result := hostRewriteDetailed("old-api.example.com")
	assert.Equal(t, "new-api.example.com", result.Host)
	assert.Equal(t, "", result.Scheme)
	assert.Equal(t, "", result.Port)
	assert.Equal(t, "", result.FullURL)
	
	// Test URL with protocol
	hostsMap = map[string]string{}
	assert.NoError(t, hostsSetup("legacy.corp=https://modern.corp.example.com"))
	
	result = hostRewriteDetailed("legacy.corp")
	assert.Equal(t, "modern.corp.example.com", result.Host)
	assert.Equal(t, "https", result.Scheme)
	assert.Equal(t, "", result.Port)
	assert.Equal(t, "https://modern.corp.example.com", result.FullURL)
	
	// Test URL with protocol and port
	hostsMap = map[string]string{}
	assert.NoError(t, hostsSetup("internal.api=http://new-internal.api:8080"))
	
	result = hostRewriteDetailed("internal.api")
	assert.Equal(t, "new-internal.api", result.Host)
	assert.Equal(t, "http", result.Scheme)
	assert.Equal(t, "8080", result.Port)
	assert.Equal(t, "http://new-internal.api:8080", result.FullURL)
	
	// Test HTTPS with non-standard port
	hostsMap = map[string]string{}
	assert.NoError(t, hostsSetup("secure.app=https://new-secure.app:9443"))
	
	result = hostRewriteDetailed("secure.app")
	assert.Equal(t, "new-secure.app", result.Host)
	assert.Equal(t, "https", result.Scheme)
	assert.Equal(t, "9443", result.Port)
	assert.Equal(t, "https://new-secure.app:9443", result.FullURL)
	
	// Test subdomain matching with URL replacement
	hostsMap = map[string]string{}
	assert.NoError(t, hostsSetup("api.legacy.com=https://api.modern.com:8443"))
	
	result = hostRewriteDetailed("service.api.legacy.com")
	assert.Equal(t, "service.api.modern.com", result.Host)
	assert.Equal(t, "https", result.Scheme)
	assert.Equal(t, "8443", result.Port)
	assert.Equal(t, "https://api.modern.com:8443", result.FullURL)
	
	// Test with no matching host
	result = hostRewriteDetailed("unmatched.example.com")
	assert.Equal(t, "unmatched.example.com", result.Host)
	assert.Equal(t, "", result.Scheme)
	assert.Equal(t, "", result.Port)
	assert.Equal(t, "", result.FullURL)
	
	// Reset for other tests
	hostsMap = map[string]string{}
}

func TestBackwardCompatibility(t *testing.T) {
	// Reset the map for clean testing
	hostsMap = map[string]string{}
	
	// Test that hostRewrite still works the same way for simple host mappings
	assert.NoError(t, hostsSetup("old.example.com=new.example.com"))
	assert.Equal(t, "new.example.com", hostRewrite("old.example.com"))
	
	// Test that hostRewrite returns just the host part for URL mappings
	hostsMap = map[string]string{}
	assert.NoError(t, hostsSetup("old.example.com=https://new.example.com:8080"))
	assert.Equal(t, "new.example.com", hostRewrite("old.example.com"))
	
	// Reset for other tests
	hostsMap = map[string]string{}
}

func TestProxyIntegration(t *testing.T) {
	// Reset the map for clean testing
	hostsMap = map[string]string{}
	
	// Test WebSocket URL conversion
	assert.NoError(t, hostsSetup("ws.example.com=https://ws.backend.com:8443"))
	
	// Create a mock request
	req := &http.Request{Host: "ws.example.com"}
	req.URL, _ = url.Parse("/socket")
	
	wsURL, err := http2ws(req)
	assert.NoError(t, err)
	assert.Equal(t, "wss://ws.backend.com:8443/socket", wsURL.String())
	
	// Test HTTP backend URL conversion
	assert.NoError(t, hostsSetup("api.example.com=http://api.backend.com:8080"))
	
	rewrite := hostRewriteDetailed("api.example.com")
	assert.Equal(t, "api.backend.com", rewrite.Host)
	assert.Equal(t, "http", rewrite.Scheme)
	assert.Equal(t, "8080", rewrite.Port)
	assert.Equal(t, "http://api.backend.com:8080", rewrite.FullURL)
	
	// Reset for other tests
	hostsMap = map[string]string{}
}
