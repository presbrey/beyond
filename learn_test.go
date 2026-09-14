package beyond

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestLearnHostScheme(t *testing.T) {
	oldTLS := tlsConfig.InsecureSkipVerify
	oldHTTPS, oldHTTP := *learnHTTPSPorts, *learnHTTPPorts
	defer func() { tlsConfig.InsecureSkipVerify = oldTLS; *learnHTTPSPorts = oldHTTPS; *learnHTTPPorts = oldHTTP }()
	tlsConfig.InsecureSkipVerify = true
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	secure := httptest.NewTLSServer(handler)
	defer secure.Close()
	plain := httptest.NewServer(handler)
	defer plain.Close()
	secureURL, _ := url.Parse(secure.URL)
	plainURL, _ := url.Parse(plain.URL)
	*learnHTTPSPorts = secureURL.Port()
	*learnHTTPPorts = plainURL.Port()
	assert.Equal(t, secure.URL, learnBase("127.0.0.1"))
	assert.Equal(t, secure.URL, learnBase(secureURL.Host))
	assert.NotNil(t, learn(secureURL.Host))
	// A plain HTTP listener on the candidate TLS port must fall back to HTTP.
	*learnHTTPSPorts = plainURL.Port()
	assert.Equal(t, plain.URL, learnBase("127.0.0.1"))
	assert.Equal(t, plain.URL, learnBase(plainURL.Host))
	assert.Equal(t, plain.URL, learnBase(plain.URL))
}
