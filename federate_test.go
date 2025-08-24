package beyond

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/assert"
)

var (
	federateServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/next":
			token := r.URL.Query().Get("token")
			if token == "" {
				w.WriteHeader(551)
				return
			}
			
			// Make request to testMux directly
			request := httptest.NewRequest("GET", "/federate/verify?token="+token, nil)
			request.Host = *host
			recorder := httptest.NewRecorder()
			testMux.ServeHTTP(recorder, request)
			
			resp := recorder.Result()
			body, _ := io.ReadAll(resp.Body)
			w.WriteHeader(resp.StatusCode)
			w.Write(body)
			return

		default:
			return

		}
	}))
)

func TestFederateSetup(t *testing.T) {
	assert.NoError(t, federateSetup())
	assert.Empty(t, federateAccessCodec)

	*federateAccessKey = "9zcNzr9ObeWnNExMXYbeXxy9CxMMz6FS6ZhSfYRwzXHTNa3ZJo7uFQ2qsWZ5u1Id"
	*federateSecretKey = "S6ZhSfYRwzXHTNa3ZJo7uFQ2qsWZ5u1Id9zcNzr9ObeWnNExMXYbeXxy9CxMMz6F"
	assert.NoError(t, federateSetup())
	assert.NotEmpty(t, federateAccessCodec)
	assert.NotEmpty(t, federateSecretCodec)
}

func TestFederateHandler(t *testing.T) {
	// Test federate endpoint without next parameter
	request := httptest.NewRequest("GET", "/federate", nil)
	request.Host = *host
	w := httptest.NewRecorder()
	testMux.ServeHTTP(w, request)
	
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, 403, resp.StatusCode)
	assert.Equal(t, "securecookie: the value is not valid\n", string(body))

	// Test federate endpoint with encoded next parameter (no auth)
	next := federateServer.URL + "/next?token="
	next, err := securecookie.EncodeMulti("next", next, federateAccessCodec...)
	assert.NoError(t, err)

	request = httptest.NewRequest("GET", "/federate?next="+url.QueryEscape(next), nil)
	request.Host = *host
	w = httptest.NewRecorder()
	testMux.ServeHTTP(w, request)
	
	resp = w.Result()
	body, _ = io.ReadAll(resp.Body)
	assert.Equal(t, *fouroOneCode, resp.StatusCode)
	assert.Contains(t, string(body), "/launch?next=https")

	// Test federate endpoint with auth cookie - should redirect to federate server
	request = httptest.NewRequest("GET", "/federate?next="+url.QueryEscape(next), nil)
	request.Host = *host
	vals := map[string]interface{}{"user": "cloud@user.com"}
	cookieValue, err := securecookie.EncodeMulti(*cookieName, &vals, store.Codecs...)
	assert.NoError(t, err)
	request.AddCookie(&http.Cookie{Name: *cookieName, Value: cookieValue})
	w = httptest.NewRecorder()
	testMux.ServeHTTP(w, request)
	
	resp = w.Result()
	body, _ = io.ReadAll(resp.Body)
	// The federate handler redirects to the federate server, so we expect a 302
	assert.Equal(t, 302, resp.StatusCode)
	assert.Contains(t, string(body), "Found")

	// Test with broken secret codec
	federateSecretCodec = []securecookie.Codec{}
	request = httptest.NewRequest("GET", "/federate?next="+url.QueryEscape(next), nil)
	request.Host = *host
	request.AddCookie(&http.Cookie{Name: *cookieName, Value: cookieValue})
	w = httptest.NewRecorder()
	testMux.ServeHTTP(w, request)
	
	resp = w.Result()
	body, _ = io.ReadAll(resp.Body)
	assert.Equal(t, 500, resp.StatusCode)
	assert.Contains(t, string(body), "securecookie: no codecs provided")
}

func TestFederateVerify500(t *testing.T) {
	req := httptest.NewRequest("GET", "http://"+*host+"/federate/verify?", nil)
	w := httptest.NewRecorder()
	testMux.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assert.Equal(t, 500, resp.StatusCode)
	assert.Equal(t, "securecookie: no codecs provided\n", string(body))
}
