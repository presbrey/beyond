package beyond

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/drewolson/testflight"
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
			handled := false
			testflight.WithServer(testMux, func(r *testflight.Requester) {
				request, err := http.NewRequest("GET", "/federate/verify?token="+token, nil)
				if err == nil {
					request.Host = *host
					response := r.Do(request)
					w.Write(response.RawBody)
					handled = true
					return
				}
			})
			if !handled {
				fmt.Fprint(w, "ERR")
				w.WriteHeader(552)
			}
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
	testflight.WithServer(testMux, func(r *testflight.Requester) {
		request, err := http.NewRequest("GET", "/federate", nil)
		request.Host = *host
		assert.NoError(t, err)
		response := r.Do(request)
		assert.Equal(t, 403, response.StatusCode)
		assert.Equal(t, "securecookie: the value is not valid\n", response.Body)

		next := federateServer.URL + "/next?token="
		next, err = securecookie.EncodeMulti("next", next, federateAccessCodec...)
		assert.NoError(t, err)

		request, err = http.NewRequest("GET", "/federate?next="+url.QueryEscape(next), nil)
		request.Host = *host
		assert.NoError(t, err)
		response = r.Do(request)
		assert.Equal(t, *fouroOneCode, response.StatusCode)
		assert.Contains(t, response.Body, "/launch?next=https")

		request, err = http.NewRequest("GET", "/federate?next="+url.QueryEscape(next), nil)
		assert.NoError(t, err)
		request.Host = *host
		vals := map[string]interface{}{"user": "cloud@user.com"}
		cookieValue, err := securecookie.EncodeMulti(*cookieName, &vals, store.Codecs...)
		assert.NoError(t, err)
		request.AddCookie(&http.Cookie{Name: *cookieName, Value: cookieValue})
		response = r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, "{\"email\":\"cloud@user.com\"}\n", response.Body)

		federateSecretCodec = []securecookie.Codec{}
		request, err = http.NewRequest("GET", "/federate?next="+url.QueryEscape(next), nil)
		assert.NoError(t, err)
		request.Host = *host
		request.AddCookie(&http.Cookie{Name: *cookieName, Value: cookieValue})
		response = r.Do(request)
		assert.Equal(t, 500, response.StatusCode)
		assert.Contains(t, response.Body, "securecookie: no codecs provided")
	})
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
