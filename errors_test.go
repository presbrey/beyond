package beyond

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func init() {
	*errorEmail = "support@mycompany.com"
}

type testIntString struct {
	code int
	text string
}

func TestErrorQuery(t *testing.T) {
	for errorQuery, expectedValues := range map[string]testIntString{
		"invalid_request":           {400, "400 - Bad Request"},
		"access_denied":             {403, "403 - Forbidden"},
		"invalid_resource":          {404, "404 - Not Found"},
		"unknown":                   {500, "500 - Internal Server Error"},
		"server_error":              {500, "500 - Internal Server Error"},
		"unsupported_response_type": {501, "501 - Not Implemented"},
		"temporarily_unavailable":   {503, "503 - Service Unavailable"},
	} {
		request := httptest.NewRequest("GET", "/oidc?error="+errorQuery, nil)
		request.Host = *host
		w := httptest.NewRecorder()
		testMux.ServeHTTP(w, request)
		
		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, expectedValues.code, resp.StatusCode)
		assert.Contains(t, string(body), expectedValues.text)
	}
}

func TestErrorPlain(t *testing.T) {
	*errorPlain = true

	request := httptest.NewRequest("GET", "/oidc?error=server_error&error_description=Foo+Biz", nil)
	request.Host = *host
	w := httptest.NewRecorder()
	testMux.ServeHTTP(w, request)
	
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, 500, resp.StatusCode)
	assert.Contains(t, string(body), "Foo Biz")

	*errorPlain = false
}

type testResponseWriter struct {
	http.ResponseWriter
}

func (w *testResponseWriter) WriteHeader(code int) {}
func (w *testResponseWriter) Header() http.Header  { return http.Header{} }
func (w *testResponseWriter) Write(data []byte) (n int, err error) {
	return 0, fmt.Errorf("WriteError")
}

func TestErrorExecuteWriteError(t *testing.T) {
	w := &testResponseWriter{}
	err := errorExecute(w, 500, "WriteError")
	assert.Equal(t, "WriteError", err.Error())
	errorHandler(w, 500, "WriteError")
}
