package beyond

import (
	"net/http"
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
