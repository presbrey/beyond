package beyond

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/presbrey/beyond/internal/authn"
	"github.com/presbrey/beyond/internal/authz"
	"github.com/stretchr/testify/assert"
)

func init() {
	// Load the allowlist for testing
	cwd, _ := os.Getwd()
	*authz.AllowlistURL = "file://" + cwd + "/example/allowlist.json"
	authz.RefreshAllowlist()
}

func TestHandlerPing(t *testing.T) {
	request := httptest.NewRequest("GET", *healthPath, nil)
	w := httptest.NewRecorder()
	testMux.ServeHTTP(w, request)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, *healthReply, string(body))
}

func TestHandlerGo(t *testing.T) {
	request := httptest.NewRequest("GET", "/test?a=1", nil)
	request.Host = "github.com"
	w := httptest.NewRecorder()
	testMux.ServeHTTP(w, request)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, *fouroOneCode, resp.StatusCode)
	assert.Equal(t, "", resp.Header.Get("Set-Cookie"))
	assert.Equal(t, "\n<script type=\"text/javascript\">\nwindow.location.replace(\"https://"+*host+"/launch?next=https%3A%2F%2Fgithub.com%2Ftest%3Fa%3D1\");\n</script>\n", string(body))
}

func TestHandlerLaunch(t *testing.T) {
	request := httptest.NewRequest("GET", "/launch?next=https%3A%2F%2Falachart.colofoo.net%2Ftest%3Fa%3D1", nil)
	request.Host = *host
	w := httptest.NewRecorder()
	testMux.ServeHTTP(w, request)

	resp := w.Result()
	assert.Equal(t, 200, resp.StatusCode)
	assert.NotEqual(t, "", resp.Header.Get("Set-Cookie"))
}

func TestHandlerOidcNoCookie(t *testing.T) {
	request := httptest.NewRequest("GET", "/oidc", nil)
	request.Host = *host
	w := httptest.NewRecorder()
	testMux.ServeHTTP(w, request)

	resp := w.Result()
	// Returns 403 because GetSession creates a new session with empty state
	// which doesn't match the query parameter state
	assert.Equal(t, 403, resp.StatusCode)
}

func TestHandlerOidcStateInvalid(t *testing.T) {
	session := authn.NewSession(*authn.CookieName)
	recorder := httptest.NewRecorder()
	assert.NoError(t, authn.GetStore().Save(recorder, session))
	cookie := strings.Split(recorder.Header().Get("Set-Cookie"), ";")[0]

	request := httptest.NewRequest("GET", "/oidc?state=test1", nil)
	request.Host = *host
	request.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	testMux.ServeHTTP(w, request)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, 403, resp.StatusCode)
	assert.Contains(t, string(body), "Invalid Browser State")
}

func TestHandlerOidcStateValid(t *testing.T) {
	session := authn.NewSession(*authn.CookieName)
	session.Values["state"] = "test1"
	recorder := httptest.NewRecorder()
	assert.NoError(t, authn.GetStore().Save(recorder, session))
	cookie := strings.Split(recorder.Header().Get("Set-Cookie"), ";")[0]

	request := httptest.NewRequest("GET", "/oidc?state=test1", nil)
	request.Host = *host
	request.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	testMux.ServeHTTP(w, request)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, 401, resp.StatusCode)
	assert.Contains(t, string(body), "oauth2:")
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
	// Test allowed host (1.1.1.1 - Cloudflare DNS)
	request := httptest.NewRequest("GET", "/cdn-cgi/trace", nil)
	request.Host = "1.1.1.1"
	w := httptest.NewRecorder()
	testMux.ServeHTTP(w, request)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "", resp.Header.Get("Set-Cookie"))
	// Cloudflare trace returns plain text with key=value pairs
	assert.Contains(t, string(body), "ip=")

	// Test blocked host (github.com)
	request = httptest.NewRequest("GET", "/.well-known/acme-challenge/test", nil)
	request.Host = "github.com"
	w = httptest.NewRecorder()
	testMux.ServeHTTP(w, request)

	resp = w.Result()
	body, _ = io.ReadAll(resp.Body)
	assert.Equal(t, 404, resp.StatusCode)
	assert.NotEqual(t, "", resp.Header.Get("Set-Cookie"))
	assert.Contains(t, string(body), "Page not found")
}

func TestHandlerXHR(t *testing.T) {
	request := httptest.NewRequest("GET", "/test?a=1", nil)
	request.Host = "github.com"
	request.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	testMux.ServeHTTP(w, request)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, *fouroOneCode, resp.StatusCode)
	assert.Equal(t, "", resp.Header.Get("Set-Cookie"))
	assert.Equal(t, "", string(body))
}

func TestNexthopInvalid(t *testing.T) {
	request := httptest.NewRequest("GET", "/favicon.ico", nil)
	request.Host = "nonexistent.example.test"
	w := httptest.NewRecorder()
	testMux.ServeHTTP(w, request)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, 404, resp.StatusCode)
	assert.Equal(t, "", resp.Header.Get("Set-Cookie"))
	assert.Contains(t, string(body), *fouroFourMessage)
}

func TestRandhex32(t *testing.T) {
	h, err := authn.RandHex32()
	assert.Len(t, h, 64)
	assert.NoError(t, err)
}
