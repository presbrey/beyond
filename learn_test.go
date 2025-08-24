package beyond

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"inet.af/tcpproxy"
)

var (
	proxy tcpproxy.Proxy
)

func init() {
	proxy.AddRoute("127.0.0.1:9443", tcpproxy.To("1.1.1.1:443"))
}

func TestLearnProxy(t *testing.T) {
	tlsConfig.InsecureSkipVerify = true
	assert.NoError(t, proxy.Start())
}

func TestLearnHostScheme(t *testing.T) {
	// Test that learnBase returns a valid URL scheme for localhost
	result := learnBase("localhost")
	assert.True(t, strings.HasPrefix(result, "http://") || strings.HasPrefix(result, "https://"))
	assert.Contains(t, result, "localhost")

	ports1 := *learnHTTPSPorts
	ports2 := *learnHTTPPorts

	learnTest1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	learnTest2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	*learnHTTPSPorts = strings.Split(learnTest1.URL, ":")[2]
	*learnHTTPPorts = strings.Split(learnTest2.URL, ":")[2]
	base1 := learnBase("127.0.0.1")
	learnTest1.Close()
	base2 := learnBase("127.0.0.1")
	learnTest2.Close()
	assert.Equal(t, learnTest2.URL, base1)
	assert.Equal(t, learnTest2.URL, base2)

	*learnHTTPSPorts = ""
	*learnHTTPPorts = "80"
	assert.Equal(t, "http://www.google.com", learnBase("www.google.com"))

	*learnHTTPSPorts = ports1
	*learnHTTPPorts = ports2
	assert.Equal(t, "https://golang.org", learnBase("golang.org"))
	assert.NotNil(t, learn("golang.org"))

	assert.Equal(t, "https://golang.org:443", learnBase("golang.org:443"))
}
