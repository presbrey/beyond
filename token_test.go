package beyond

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/drewolson/testflight"
	"github.com/stretchr/testify/assert"
)

func init() {
	// Setup file transport for ACL
	t := &http.Transport{}
	t.RegisterProtocol("file", http.NewFileTransport(http.Dir("/")))
	httpACL.Transport = t
	
	// Load the fence and sites configuration for testing
	cwd, _ := os.Getwd()
	*fenceURL = "file://" + cwd + "/example/fence.json"
	*sitesURL = "file://" + cwd + "/example/sites.json"
	refreshFence()
	refreshSites()
	
	// Setup token authentication
	*tokenBase = tokenServer.URL + "/?access_token="
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
		if r.URL.Query().Get("access_token") == "invalid" {
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
		err := json.NewEncoder(w).Encode(tokenUser{Login: user})
		if err != nil {
			errorHandler(w, 500, err.Error())
		}
	}))
)

func TestTokenError(t *testing.T) {
	*tokenBase = "https://foo.bar?"

	r, err := http.NewRequest("GET", "/", nil)
	assert.NoError(t, err)

	assert.Equal(t, "", tokenAuth(r))
	r.Header.Set("Authorization", "token test")
	assert.Equal(t, "", tokenAuth(r))

	*tokenBase = tokenServer.URL + "/?access_token="
	r.Header.Set("Authorization", "token invalid")
	assert.Equal(t, "", tokenAuth(r))
}

func TestTokenBasic(t *testing.T) {
	r, err := http.NewRequest("GET", "/", nil)
	assert.NoError(t, err)

	r.SetBasicAuth(tokenTestUserTokens["user1"], "x-oauth-basic")
	login1 := tokenAuth(r)
	r.SetBasicAuth("", tokenTestUserTokens["user1"])
	login2 := tokenAuth(r)
	assert.Equal(t, "user1", login1)
	assert.Equal(t, "user1", login2)

	r.SetBasicAuth(tokenTestUserTokens["user1"], "foobar")
	assert.Equal(t, "", tokenAuth(r))
}

func TestTokenFederation(t *testing.T) {
	r, err := http.NewRequest("GET", "/", nil)
	assert.NoError(t, err)

	r.Header.Set("Authorization", "token test")
	assert.Equal(t, "", tokenAuth(r))

	r.Header.Set("Authorization", "token "+tokenTestUserTokens["user1"])
	login1 := tokenAuth(r)
	login2 := tokenAuth(r)
	assert.Equal(t, "user1", login1)
	assert.Equal(t, "user1", login2)
}

func TestTokenSuccess(t *testing.T) {
	testflight.WithServer(testMux, func(r *testflight.Requester) {
		request, err := http.NewRequest("GET", "/ip", nil)
		assert.Nil(t, err)
		request.Header.Set("Authorization", "Token "+tokenTestUserTokens["user1"])
		request.Host = "httpbin.org"
		response := r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, "{\n  \"origin\"", strings.Split(response.Body, ":")[0])
	})
	testflight.WithServer(testMux, func(r *testflight.Requester) {
		request, err := http.NewRequest("GET", "/ip", nil)
		assert.Nil(t, err)
		request.SetBasicAuth("user1", tokenTestUserTokens["user1"])
		request.Host = "httpbin.org"
		response := r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, "{\n  \"origin\"", strings.Split(response.Body, ":")[0])
	})

	// expect ACL 403
	testflight.WithServer(testMux, func(r *testflight.Requester) {
		request, err := http.NewRequest("GET", "/", nil)
		assert.Nil(t, err)
		request.Header.Set("Authorization", "Token "+tokenTestUserTokens["vendor@gmail.com"])
		request.Host = "example.com"
		response := r.Do(request)
		assert.Equal(t, 403, response.StatusCode)
		assert.Contains(t, response.Body, "Access Denied")
	})
}
