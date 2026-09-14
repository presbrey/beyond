package beyond

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/presbrey/beyond/internal/authn"
	"github.com/presbrey/beyond/internal/authz"
	"github.com/stretchr/testify/assert"
)

func init() {
	// Setup file transport for ACL
	t := &http.Transport{}
	t.RegisterProtocol("file", http.NewFileTransport(http.Dir("/")))
	client := &http.Client{Transport: t}
	authz.SetHTTPClient(client)

	// Load the fence and sites configuration for testing
	cwd, _ := os.Getwd()
	*authz.FenceURL = "file://" + cwd + "/example/fence.json"
	*authz.SitesURL = "file://" + cwd + "/example/sites.json"
	authz.RefreshFence()
	authz.RefreshSites()

	// Setup token authentication
	*authn.TokenBase = tokenServer.URL + "/?access_token="
}

var (
	tokenTestTokenUsers = map[string]string{
		"932928c0a4edf9878ee0257a1d8f4d06adaaffee": "user1",
		"257a1d8f4d06adaaffee932928c0a4edf9878ee0": "vendor@gmail.com",
	}
	tokenTestUserTokens = map[string]string{
		"user1":            "932928c0a4edf9878ee0257a1d8f4d06adaaffee",
		"vendor@gmail.com": "257a1d8f4d06adaaffee932928c0a4edf9878ee0",
	}

	tokenServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer invalid" {
			_, err := io.WriteString(w, "{")
			if err != nil {
				errorHandler(w, 500, err.Error())
			}
			return
		}
		authorization := r.Header.Get("Authorization")
		user := tokenTestTokenUsers[r.URL.Query().Get("access_token")]
		if user == "" && strings.Contains(authorization, " ") {
			user = tokenTestTokenUsers[strings.Split(authorization, " ")[1]]
		}
		err := json.NewEncoder(w).Encode(authn.TokenUser{Login: user})
		if err != nil {
			errorHandler(w, 500, err.Error())
		}
	}))
)

func TestTokenError(t *testing.T) {
	*authn.TokenBase = ":"

	r, err := http.NewRequest("GET", "/", nil)
	assert.NoError(t, err)

	assert.Equal(t, "", authn.TokenAuth(r))
	r.Header.Set("Authorization", "token test")
	assert.Equal(t, "", authn.TokenAuth(r))

	*authn.TokenBase = tokenServer.URL + "/?access_token="
	r.Header.Set("Authorization", "token invalid")
	assert.Equal(t, "", authn.TokenAuth(r))
}

func TestTokenBasic(t *testing.T) {
	r, err := http.NewRequest("GET", "/", nil)
	assert.NoError(t, err)

	r.SetBasicAuth(tokenTestUserTokens["user1"], "x-oauth-basic")
	login1 := authn.TokenAuth(r)
	r.SetBasicAuth("", tokenTestUserTokens["user1"])
	login2 := authn.TokenAuth(r)
	assert.Equal(t, "user1", login1)
	assert.Equal(t, "user1", login2)

	r.SetBasicAuth(tokenTestUserTokens["user1"], "foobar")
	assert.Equal(t, "", authn.TokenAuth(r))
}

func TestTokenFederation(t *testing.T) {
	r, err := http.NewRequest("GET", "/", nil)
	assert.NoError(t, err)

	r.Header.Set("Authorization", "token test")
	assert.Equal(t, "", authn.TokenAuth(r))

	r.Header.Set("Authorization", "token "+tokenTestUserTokens["user1"])
	login1 := authn.TokenAuth(r)
	login2 := authn.TokenAuth(r)
	assert.Equal(t, "user1", login1)
	assert.Equal(t, "user1", login2)
}

func TestTokenSuccess(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "authenticated backend") }))
	defer backend.Close()
	target, err := url.Parse(backend.URL)
	assert.NoError(t, err)
	const backendHost = "token.example.test"
	hostProxy.Store(backendHost, newSHRP(target))
	defer hostProxy.Delete(backendHost)
	// Test token authentication with Authorization header
	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Set("Authorization", "Token "+tokenTestUserTokens["user1"])
	request.Host = backendHost
	w := httptest.NewRecorder()
	testMux.ServeHTTP(w, request)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, 200, resp.StatusCode)
	// The local backend is reached after successful authentication.
	assert.Equal(t, "authenticated backend", string(body))

	// Test token authentication with Basic Auth
	request = httptest.NewRequest("GET", "/", nil)
	request.SetBasicAuth("user1", tokenTestUserTokens["user1"])
	request.Host = backendHost
	w = httptest.NewRecorder()
	testMux.ServeHTTP(w, request)

	resp = w.Result()
	body, _ = io.ReadAll(resp.Body)
	assert.Equal(t, 200, resp.StatusCode)
	// The local backend is reached after successful authentication.
	assert.Equal(t, "authenticated backend", string(body))

	// Test ACL 403 - vendor@gmail.com should be blocked by ACL
	request = httptest.NewRequest("GET", "/", nil)
	request.Header.Set("Authorization", "Token "+tokenTestUserTokens["vendor@gmail.com"])
	request.Host = "example.com"
	w = httptest.NewRecorder()
	testMux.ServeHTTP(w, request)

	resp = w.Result()
	body, _ = io.ReadAll(resp.Body)
	assert.Equal(t, 403, resp.StatusCode)
	assert.Contains(t, string(body), "Access Denied")
}
