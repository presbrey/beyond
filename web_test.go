package beyond

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

	// Test token for basic auth testing
	webTestUserTokens = map[string]string{
		"user1": "932928c0a4edf9878ee0257a1d8f4d06adaaffee",
	}
)

func init() {
	Setup()
	testMux = NewMux()
}

func TestWebPOST(t *testing.T) {
	server := httptest.NewServer(testMux)
	defer server.Close()

	// Test successful request with valid basic auth
	request, err := http.NewRequest("POST", server.URL+"/", strings.NewReader("ping"))
	assert.NoError(t, err)
	request.Host = echoServer.URL[7:] // strip the http://
	request.SetBasicAuth("", webTestUserTokens["user1"])

	client := &http.Client{}
	response, err := client.Do(request)
	assert.NoError(t, err)
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Equal(t, "pong", string(body))

	// Test request without authentication
	request, err = http.NewRequest("POST", server.URL+"/", strings.NewReader("aliens"))
	assert.NoError(t, err)
	request.Host = echoServer.URL[7:] // strip the http://

	response, err = client.Do(request)
	assert.NoError(t, err)
	defer response.Body.Close()

	assert.Equal(t, *fouroOneCode, response.StatusCode)
}
