package beyond

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/drewolson/testflight"
	"github.com/stretchr/testify/assert"
)

var (
	echoServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			log.Println(err)
		}
		switch string(b) {
		case "ping":
			fmt.Fprint(w, "pong")
		default:
			fmt.Fprint(w, string(b))
		}
	}))

	testMux http.Handler
)

func init() {
	testMux = NewMux()
}

func TestWebPOST(t *testing.T) {
	testflight.WithServer(testMux, func(rq *testflight.Requester) {
		request, err := http.NewRequest("POST", "/", strings.NewReader("ping"))
		request.Host = echoServer.URL[7:] // strip the http://
		assert.NoError(t, err)
		request.SetBasicAuth("", tokenTestUserTokens["user1"])
		response := rq.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, "pong", response.Body)

		request, err = http.NewRequest("POST", "/", strings.NewReader("aliens"))
		request.Host = echoServer.URL // including http://
		assert.NoError(t, err)
		request.SetBasicAuth("", tokenTestUserTokens["user1"])
		response = rq.Do(request)
		assert.Equal(t, 400, response.StatusCode)
		assert.Contains(t, response.Body, "400 Bad Request")

		request, err = http.NewRequest("POST", "/", strings.NewReader("aliens"))
		request.Host = echoServer.URL[7:] // strip the http://
		assert.NoError(t, err)
		response = rq.Do(request)
		assert.Equal(t, *fouroOneCode, response.StatusCode)
	})
}
