package beyond

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/drewolson/testflight"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
)

func init() {
	// Load the allowlist for testing
	cwd, _ := os.Getwd()
	*allowlistURL = "file://" + cwd + "/example/allowlist.json"
	refreshAllowlist()
}

func TestHandlerPing(t *testing.T) {
	testflight.WithServer(testMux, func(r *testflight.Requester) {
		request, err := http.NewRequest("GET", *healthPath, nil)
		assert.Nil(t, err)
		response := r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, *healthReply, response.Body)
	})
}

func TestHandlerGo(t *testing.T) {
	testflight.WithServer(testMux, func(r *testflight.Requester) {
		request, err := http.NewRequest("GET", "/test?a=1", nil)
		assert.Nil(t, err)
		request.Host = "github.com"
		response := r.Do(request)
		assert.Equal(t, *fouroOneCode, response.StatusCode)
		assert.Equal(t, "", response.Header.Get("Set-Cookie"))
		assert.Equal(t, "\n<script type=\"text/javascript\">\nwindow.location.replace(\"https://"+*host+"/launch?next=https%3A%2F%2Fgithub.com%2Ftest%3Fa%3D1\");\n</script>\n", response.Body)
	})
}

func TestHandlerLaunch(t *testing.T) {
	testflight.WithServer(testMux, func(r *testflight.Requester) {
		request, err := http.NewRequest("GET", "/launch?next=https%3A%2F%2Falachart.colofoo.net%2Ftest%3Fa%3D1", nil)
		assert.Nil(t, err)
		request.Host = *host
		response := r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.NotEqual(t, "", response.Header.Get("Set-Cookie"))
	})
}

func TestHandlerOidcNoCookie(t *testing.T) {
	testflight.WithServer(testMux, func(r *testflight.Requester) {
		request, err := http.NewRequest("GET", "/oidc", nil)
		assert.Nil(t, err)
		request.Host = *host
		response := r.Do(request)
		assert.Equal(t, 400, response.StatusCode)
	})
}

func TestHandlerOidcStateInvalid(t *testing.T) {
	session := store.New(*cookieName)
	recorder := httptest.NewRecorder()
	assert.NoError(t, store.Save(recorder, session))
	cookie := strings.Split(recorder.Header().Get("Set-Cookie"), ";")[0]

	testflight.WithServer(testMux, func(r *testflight.Requester) {
		request, err := http.NewRequest("GET", "/oidc?state=test1", nil)
		assert.Nil(t, err)
		request.Host = *host
		request.Header.Set("Cookie", cookie)
		response := r.Do(request)
		assert.Equal(t, 403, response.StatusCode)
		assert.Contains(t, response.Body, "Invalid Browser State")
	})
}

func TestHandlerOidcStateValid(t *testing.T) {
	session := store.New(*cookieName)
	session.Values["state"] = "test1"
	recorder := httptest.NewRecorder()
	assert.NoError(t, store.Save(recorder, session))
	cookie := strings.Split(recorder.Header().Get("Set-Cookie"), ";")[0]

	testflight.WithServer(testMux, func(r *testflight.Requester) {
		request, err := http.NewRequest("GET", "/oidc?state=test1", nil)
		assert.Nil(t, err)
		request.Host = *host
		request.Header.Set("Cookie", cookie)
		response := r.Do(request)
		assert.Equal(t, 401, response.StatusCode)
		assert.Contains(t, response.Body, "oauth2: cannot fetch token: ")
	})
}

func TestHandlerWebsocket(t *testing.T) {
	t.SkipNow()

	server := httptest.NewServer(testMux)
	x, y, err := websocket.DefaultDialer.Dial(strings.Replace(server.URL, "http://", "ws://", 1)+"/", http.Header{"Host": []string{"echo.websocket.org"}})
	assert.NoError(t, err)
	err = x.WriteMessage(websocket.TextMessage, []byte("BEYOND"))
	assert.NoError(t, err)

	typ, msg, err := x.ReadMessage()
	assert.Equal(t, 101, y.StatusCode)
	assert.Equal(t, websocket.TextMessage, typ)
	assert.Equal(t, "BEYOND", string(msg))
	assert.NoError(t, err)
	server.Close()
}

func TestHandlerAllowlist(t *testing.T) {
	testflight.WithServer(testMux, func(r *testflight.Requester) {
		request, err := http.NewRequest("GET", "/", nil)
		assert.Nil(t, err)
		request.Host = "httpbin.org"
		response := r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, "", response.Header.Get("Set-Cookie"))
		assert.Contains(t, string(response.RawBody), "httpbin.org")
	})
	testflight.WithServer(testMux, func(r *testflight.Requester) {
		request, err := http.NewRequest("GET", "/.well-known/acme-challenge/test", nil)
		assert.Nil(t, err)
		request.Host = "github.com"
		response := r.Do(request)
		assert.Equal(t, 404, response.StatusCode)
		assert.NotEqual(t, "", response.Header.Get("Set-Cookie"))
		assert.Contains(t, response.Body, "Page not found")
	})
}

func TestHandlerXHR(t *testing.T) {
	testflight.WithServer(testMux, func(r *testflight.Requester) {
		request, err := http.NewRequest("GET", "/test?a=1", nil)
		assert.Nil(t, err)
		request.Host = "github.com"
		request.Header.Set("X-Requested-With", "XMLHttpRequest")
		response := r.Do(request)
		assert.Equal(t, *fouroOneCode, response.StatusCode)
		assert.Equal(t, "", response.Header.Get("Set-Cookie"))
		assert.Equal(t, "", response.Body)
	})
}

func TestNexthopInvalid(t *testing.T) {
	testflight.WithServer(testMux, func(r *testflight.Requester) {
		request, err := http.NewRequest("GET", "/favicon.ico", nil)
		assert.Nil(t, err)
		request.Host = "nonexistent.example.test"
		response := r.Do(request)
		assert.Equal(t, 404, response.StatusCode)
		assert.Equal(t, "", response.Header.Get("Set-Cookie"))
		assert.Contains(t, response.Body, *fouroFourMessage)
	})
}

func TestRandhex32(t *testing.T) {
	h, err := randhex32()
	assert.Len(t, h, 64)
	assert.NoError(t, err)
}
