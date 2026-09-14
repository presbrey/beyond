package beyond

import (
	"fmt"
	"github.com/gorilla/websocket"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/presbrey/beyond/internal/authn"
	"github.com/presbrey/beyond/internal/authz"
	"github.com/stretchr/testify/require"
)

func TestProxyMappingBackendPorts(t *testing.T) {
	oldMap := authz.GetHostsMap()
	oldLearn := *learnNexthops
	*learnNexthops = true
	t.Cleanup(func() { authz.SetHostsMap(oldMap); *learnNexthops = oldLearn })
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "A") }))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "B") }))
	defer b.Close()
	authz.SetHostsMap(map[string]string{"a.example": a.URL, "b.example": b.URL})
	defer hostProxy.Delete(a.URL)
	defer hostProxy.Delete(b.URL)
	for _, tt := range []struct{ host, want string }{{"a.example", "A"}, {"b.example", "B"}, {"a.example", "A"}} {
		request := httptest.NewRequest("GET", "http://"+tt.host+"/", nil)
		response := httptest.NewRecorder()
		nexthop(response, request)
		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, tt.want, response.Body.String())
	}
}

func TestSubdomainProxyTarget(t *testing.T) {
	oldMap := authz.GetHostsMap()
	t.Cleanup(func() { authz.SetHostsMap(oldMap) })
	authz.SetHostsMap(map[string]string{"legacy.example": "https://backend.example:8443"})
	rewrite := authz.HostRewriteDetailed("service.legacy.example")
	target, err := url.Parse(rewrite.FullURL)
	require.NoError(t, err)
	proxy := newSHRP(target)
	request := httptest.NewRequest("GET", "https://service.legacy.example/path?key=value", nil)
	proxy.Director(request)
	require.Equal(t, "https://service.backend.example:8443/path?key=value", request.URL.String())
	request = httptest.NewRequest("GET", "https://service.legacy.example/path?key=value", nil)
	ws, err := http2ws(request)
	require.NoError(t, err)
	require.Equal(t, "wss://service.backend.example:8443/path?key=value", ws.String())
}

func TestHostsOnlyRestrictsAllowlistedPaths(t *testing.T) {
	oldMap, oldOnly := authz.GetHostsMap(), *authz.HostsOnly
	t.Cleanup(func() { authz.SetHostsMap(oldMap); *authz.HostsOnly = oldOnly })
	authz.SetHostsMap(map[string]string{"allowed.example": "backend.example"})
	*authz.HostsOnly = true
	request := httptest.NewRequest("GET", "http://unmapped.example/.well-known/acme-challenge/test", nil)
	require.True(t, authz.Allowlisted(request))
	response := httptest.NewRecorder()
	handler(response, request)
	require.Equal(t, http.StatusForbidden, response.Code)
	require.Contains(t, response.Body.String(), "Host not allowed")
}

func TestMappedProxyWithLearningDisabled(t *testing.T) {
	oldMap, oldLearn := authz.GetHostsMap(), *learnNexthops
	oldSites := authz.GetSitesMap("release-regression")
	t.Cleanup(func() {
		authz.SetHostsMap(oldMap)
		*learnNexthops = oldLearn
		authz.SetSitesMap("release-regression", oldSites)
		require.NoError(t, reproxy())
	})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "configured") }))
	defer backend.Close()
	authz.SetHostsMap(map[string]string{"configured.example": backend.URL})
	authz.SetSitesMap("release-regression", map[string]bool{backend.URL: true})
	require.NoError(t, reproxy())
	*learnNexthops = false
	response := httptest.NewRecorder()
	nexthop(response, httptest.NewRequest("GET", "https://configured.example/", nil))
	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "configured", response.Body.String())
}

func TestOIDCRejectsConsumedState(t *testing.T) {
	session := authn.NewSession(*authn.CookieName)
	session.Values["state"] = ""
	response := httptest.NewRecorder()
	require.NoError(t, session.Save(response))
	request := httptest.NewRequest("GET", "https://"+*host+"/oidc?code=unused", nil)
	request.AddCookie(response.Result().Cookies()[0])
	response = httptest.NewRecorder()
	handleOIDC(response, request)
	require.Equal(t, http.StatusForbidden, response.Code)
}

func TestRedirectEscaping(t *testing.T) {
	response := httptest.NewRecorder()
	jsRedirect(response, "https://app.example/\"</script><script>alert(1)</script>")
	require.NotContains(t, response.Body.String(), "<script>alert(1)")
	require.Contains(t, response.Body.String(), `\u003c/script\u003e`)
	response = httptest.NewRecorder()
	jsRedirect(response, "javascript:alert(1)")
	require.Contains(t, response.Body.String(), `window.location.replace("/")`)
}

func TestWebsocketMappingPreservesEscapedPath(t *testing.T) {
	oldMap := authz.GetHostsMap()
	t.Cleanup(func() { authz.SetHostsMap(oldMap) })
	authz.SetHostsMap(map[string]string{"ws.example": "https://backend.example/base?fixed=1"})
	target, err := http2ws(httptest.NewRequest("GET", "https://ws.example/a%2Fb?request=2", nil))
	require.NoError(t, err)
	require.Equal(t, "wss://backend.example/base/a%2Fb?fixed=1&request=2", target.String())
}

func TestWebSocketMappedBackendEcho(t *testing.T) {
	oldMap, oldLearn := authz.GetHostsMap(), *learnNexthops
	t.Cleanup(func() { authz.SetHostsMap(oldMap); *learnNexthops = oldLearn })
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		kind, message, err := connection.ReadMessage()
		if err == nil {
			_ = connection.WriteMessage(kind, message)
		}
	}))
	defer backend.Close()
	authz.SetHostsMap(map[string]string{"ws.example": backend.URL})
	*learnNexthops = true
	defer hostProxy.Delete(backend.URL)
	session := authn.NewSession(*authn.CookieName)
	session.Values["user"] = "websocket@example.com"
	cookieResponse := httptest.NewRecorder()
	require.NoError(t, session.Save(cookieResponse))
	frontend := httptest.NewServer(http.HandlerFunc(handler))
	defer frontend.Close()
	headers := http.Header{"Host": {"ws.example"}, "Cookie": {cookieResponse.Result().Cookies()[0].String()}}
	connection, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(frontend.URL, "http")+"/socket", headers)
	require.NoError(t, err)
	defer connection.Close()
	require.Equal(t, http.StatusSwitchingProtocols, response.StatusCode)
	require.NoError(t, connection.SetReadDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, connection.WriteMessage(websocket.TextMessage, []byte("release echo")))
	kind, message, err := connection.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, websocket.TextMessage, kind)
	require.Equal(t, "release echo", string(message))
}
