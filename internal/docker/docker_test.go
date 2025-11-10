package docker

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/presbrey/beyond/internal/authn"

	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/assert"
)

const dockerToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImU3NDFhODNlODBhMzYwZWVhYmM1NDExZWE3NjE5MmM4NzdjMjdlZjJjYmZmNGQxMWQwZTExN2IyNzRjMDhkNWEifQ.eyJhY2Nlc3MiOltdLCJjb250ZXh0Ijp7ImVudGl0eV9raW5kIjoidXNlciIsImtpbmQiOiJ1c2VyIiwidmVyc2lvbiI6MiwiY29tLmFwb3N0aWxsZS5yb290IjoiJGRpc2FibGVkIiwidXNlciI6ImpvZSIsImVudGl0eV9yZWZlcmVuY2UiOiJjY2VhYmFhOS1mZmM5LTQ4MWUtOTdhZS1iZmMzYTExODMxNDAifSwiYXVkIjpudWxsLCJleHAiOjE1OTM5MTE3MzEsImlzcyI6InF1YXkiLCJpYXQiOjE1OTM5MDgxMzEsIm5iZiI6MTU5MzkwODEzMSwic3ViIjoiam9lIn0.VCZnfwtoJgpEh2U5sAHZlIJAm5pWLnwZVRoH4wnPy6jCQ4ZVw4gUNfZ4xQdBa1nDW-Zc3-iaTGCpVX12bEpaA-b98A7vzN0w6F8HCXij4QXLHGhGibxDO7k5UyPziBQCCXXB960ZVItkyttPsnCFgCPqhAwB5e3acuKKfJgtd-r8qkGXUAKIrk3zJPQvzzb4aI0poBcZh822r4hFY3BvjMlXeR4cKTzdn-96p5ZDj7zCYZanB81vVuENDhxxy_aGLwQWRp3p9GApVgcZCO2WKFDp-P7YYVpcZ5bc7ZlqWBy9RLn6wFGePAykygXwJfdkoeC2ShaHusLTNvqLMoMUYw"

var (
	dockerHost       string
	dockerTestServer *httptest.Server
	testMux          *http.ServeMux
)

func init() {
	// Setup authn for testing
	*authn.CookieKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	authn.SetupSession()

	dockerTestServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.URL)
		w.Header().Set("WWW-Authenticate", "always-overwrite")
		switch r.Header.Get("Authorization") {
		case "":
			w.WriteHeader(401)
			fmt.Fprint(w, "{\"errors\":[{\"code\":\"UNAUTHORIZED\",\"detail\":{},")
		case "err":
			w.WriteHeader(200)
			fmt.Fprint(w, `{"token":`)
		default:
			w.WriteHeader(200)
			fmt.Fprint(w, `{"token":"`+dockerToken+`"}`)
		}
	}))
	// Extract just the host part from the test server URL for use in tests
	u, _ := url.Parse(dockerTestServer.URL)
	dockerHost = u.Host
	*DockerBase = dockerTestServer.URL
	*DockerScheme = "http"
	Setup(*DockerBase)

	// Setup test mux
	testMux = http.NewServeMux()
	for _, srv := range GetServers() {
		srv.RegisterHandlers(testMux)
	}
}

func TestDockerSetup(t *testing.T) {
	err := Setup(":")
	assert.Error(t, err)
}

func TestDockerV2(t *testing.T) {
	// Test v2/ endpoint
	req := httptest.NewRequest("GET", "/v2/", nil)
	req.Host = dockerHost
	req.Header.Set("User-Agent", "docker/1.12.6 go/go1.7.4")
	w := httptest.NewRecorder()
	testMux.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, 401, resp.StatusCode)
	assert.Equal(t, "", string(body))
	assert.True(t, strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer realm="))

	// Test v2/auth with basic auth
	req = httptest.NewRequest("GET", "/v2/auth?account=joe&client_id=docker&offline_token=true&service=docker.colofoo.net", nil)
	req.Host = dockerHost
	req.SetBasicAuth("joe", "secret0")
	req.Header.Set("User-Agent", "docker/1.12.6 go/go1.7.4")
	w = httptest.NewRecorder()
	testMux.ServeHTTP(w, req)

	resp = w.Result()
	body, _ = io.ReadAll(resp.Body)
	assert.Equal(t, 200, resp.StatusCode)
	assert.True(t, strings.HasPrefix(string(body), "{\"token\":\""))

	v := map[string]interface{}{}
	err := json.Unmarshal(body, &v)
	assert.NoError(t, err)
	token := v["token"].(string)
	assert.NotZero(t, token)

	assert.True(t, len(token) > 500)
	err = securecookie.DecodeMulti("token", token, &token, authn.GetStore().Codecs...)
	assert.NoError(t, err)
	assert.Equal(t, token, dockerToken)
	token = v["token"].(string)

	// Test v2/auth with error authorization
	req = httptest.NewRequest("GET", "/v2/auth", nil)
	req.Host = dockerHost
	req.Header.Set("Authorization", "err")
	req.Header.Set("User-Agent", "docker/1.12.6 go/go1.7.4")
	w = httptest.NewRecorder()
	testMux.ServeHTTP(w, req)

	resp = w.Result()
	body, _ = io.ReadAll(resp.Body)
	assert.Equal(t, 502, resp.StatusCode)
	assert.Equal(t, "", string(body))

	// Test v2/namespaces with valid token
	req = httptest.NewRequest("GET", "/v2/namespaces", nil)
	req.Host = dockerHost
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "docker/1.12.6 go/go1.7.4")
	w = httptest.NewRecorder()
	testMux.ServeHTTP(w, req)

	resp = w.Result()
	body, _ = io.ReadAll(resp.Body)
	assert.Equal(t, 200, resp.StatusCode)
	assert.True(t, strings.HasPrefix(string(body), "{\"token\":\""))

	// Test v2/namespaces with truncated (invalid) token
	token = token[:len(token)/2]
	req = httptest.NewRequest("GET", "/v2/namespaces", nil)
	req.Host = dockerHost
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "docker/1.12.6 go/go1.7.4")
	w = httptest.NewRecorder()
	testMux.ServeHTTP(w, req)

	resp = w.Result()
	body, _ = io.ReadAll(resp.Body)
	assert.Equal(t, 401, resp.StatusCode)
	assert.Equal(t, "", string(body))
}
