package beyond

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/drewolson/testflight"
	"github.com/gorilla/securecookie"

	"github.com/stretchr/testify/assert"
)

const dockerToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImU3NDFhODNlODBhMzYwZWVhYmM1NDExZWE3NjE5MmM4NzdjMjdlZjJjYmZmNGQxMWQwZTExN2IyNzRjMDhkNWEifQ.eyJhY2Nlc3MiOltdLCJjb250ZXh0Ijp7ImVudGl0eV9raW5kIjoidXNlciIsImtpbmQiOiJ1c2VyIiwidmVyc2lvbiI6MiwiY29tLmFwb3N0aWxsZS5yb290IjoiJGRpc2FibGVkIiwidXNlciI6ImpvZSIsImVudGl0eV9yZWZlcmVuY2UiOiJjY2VhYmFhOS1mZmM5LTQ4MWUtOTdhZS1iZmMzYTExODMxNDAifSwiYXVkIjpudWxsLCJleHAiOjE1OTM5MTE3MzEsImlzcyI6InF1YXkiLCJpYXQiOjE1OTM5MDgxMzEsIm5iZiI6MTU5MzkwODEzMSwic3ViIjoiam9lIn0.VCZnfwtoJgpEh2U5sAHZlIJAm5pWLnwZVRoH4wnPy6jCQ4ZVw4gUNfZ4xQdBa1nDW-Zc3-iaTGCpVX12bEpaA-b98A7vzN0w6F8HCXij4QXLHGhGibxDO7k5UyPziBQCCXXB960ZVItkyttPsnCFgCPqhAwB5e3acuKKfJgtd-r8qkGXUAKIrk3zJPQvzzb4aI0poBcZh822r4hFY3BvjMlXeR4cKTzdn-96p5ZDj7zCYZanB81vVuENDhxxy_aGLwQWRp3p9GApVgcZCO2WKFDp-P7YYVpcZ5bc7ZlqWBy9RLn6wFGePAykygXwJfdkoeC2ShaHusLTNvqLMoMUYw"

var dockerHost = "host.docker.internal"

func init() {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	testServer.URL = strings.Replace(testServer.URL, "127.0.0.1", dockerHost, -1)
	*dockerBase = testServer.URL
	*dockerScheme = "http"
	dockerSetup(*dockerBase)
}

func TestDockerIE(t *testing.T) {
	req, err := http.NewRequest("GET", "http://"+dockerHost+"/", nil)
	assert.NoError(t, err)
	req.Header.Set("User-Agent", "MSIE")
	testMux.ServeHTTP(nil, req)
	setCacheControl(nil)
	jsRedirect(nil, "")
	login(nil, req)
}

func TestDockerV2(t *testing.T) {
	t.SkipNow()

	err := dockerSetup(":")
	assert.Error(t, err)

	testflight.WithServer(testMux, func(r *testflight.Requester) {
		v2get := r.Get("/v2/auth")
		assert.Equal(t, 418, v2get.StatusCode)

		req, err := http.NewRequest("GET", "/v2/", nil)
		assert.NoError(t, err)
		req.Host = dockerHost
		req.Header.Set("User-Agent", "docker/1.12.6 go/go1.7.4")

		resp := r.Do(req)
		assert.Equal(t, 401, resp.StatusCode)
		assert.Equal(t, "", resp.Body)
		// assert.Equal(t, `Bearer realm="`+*dockerBase+`/v2/auth",service="docker.colofoo.net"`, resp.Header.Get("WWW-Authenticate"))
		assert.True(t, strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer realm="))

		req, err = http.NewRequest("GET", "/v2/auth?account=joe&client_id=docker&offline_token=true&service=docker.colofoo.net", nil)
		assert.NoError(t, err)
		req.Host = dockerHost
		req.SetBasicAuth("joe", "secret0")
		req.Header.Set("User-Agent", "docker/1.12.6 go/go1.7.4")

		resp = r.Do(req)
		assert.Equal(t, 200, resp.StatusCode)
		assert.True(t, strings.HasPrefix(resp.Body, "{\"token\":\""))

		v := map[string]interface{}{}
		err = json.Unmarshal([]byte(resp.Body), &v)
		assert.NoError(t, err)
		token := v["token"].(string)
		assert.NotZero(t, token)

		assert.True(t, len(token) > 500)
		err = securecookie.DecodeMulti("token", token, &token, store.Codecs...)
		assert.NoError(t, err)
		assert.Equal(t, token, dockerToken)
		token = v["token"].(string)

		req, err = http.NewRequest("GET", "/v2/auth", nil)
		assert.NoError(t, err)
		req.Host = dockerHost
		req.Header.Set("Authorization", "err")
		req.Header.Set("User-Agent", "docker/1.12.6 go/go1.7.4")
		resp = r.Do(req)
		assert.Equal(t, 502, resp.StatusCode)
		assert.Equal(t, "", resp.Body)

		req, err = http.NewRequest("GET", "/v2/namespaces", nil)
		assert.NoError(t, err)
		req.Host = dockerHost
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("User-Agent", "docker/1.12.6 go/go1.7.4")
		resp = r.Do(req)
		assert.Equal(t, 200, resp.StatusCode)
		assert.True(t, strings.HasPrefix(resp.Body, "{\"token\":\""))

		token = token[:len(token)/2]

		req, err = http.NewRequest("GET", "/v2/namespaces", nil)
		assert.NoError(t, err)
		req.Host = dockerHost
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("User-Agent", "docker/1.12.6 go/go1.7.4")

		resp = r.Do(req)
		assert.Equal(t, 401, resp.StatusCode)
		assert.Equal(t, "", resp.Body)
	})
}
