package beyond

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/drewolson/testflight"
	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

var (
	oidcServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			err := json.NewEncoder(w).Encode(oidcWK)
			if err != nil {
				http.Error(w, err.Error(), 500)
			}
			return

		case "/token":
			fmt.Fprint(w, `{"typ":"JWT","alg":"HS256"}`)
			return

		case "/next":
			fmt.Fprint(w, "NEXT")
			return

		default:
			WithField("path", r.URL.Path).Error("Invalid OIDC Request")
			return

		}
	}))
	oidcWK = struct {
		Issuer                string
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
	}{
		"/issuer",
		"/authorize",
		"/token",
	}
)

type oidcMock struct{}

func (o *oidcMock) AuthCodeURL(state string, opt ...oauth2.AuthCodeOption) string {
	return oidcServer.URL + "/AuthCodeURL"
}

func (o *oidcMock) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	token := &oauth2.Token{}
	token.AccessToken = "AccessToken"
	token.Expiry = time.Now().Add(time.Hour)
	token = token.WithExtra(map[string]interface{}{"id_token": "IDToken"})
	return token, nil
}

func (o *oidcMock) Verify(ctx context.Context, raw string) (*oidc.IDToken, error) {
	if raw == "err" {
		return nil, http.ErrHijacked
	}
	token := &oidc.IDToken{}

	getOIDCClaims = func(claims *oidcClaims, tokenID *oidc.IDToken) error {
		claims.Email = "user3@domain3.com"
		return nil
	}
	if raw == "claimsErr" {
		getOIDCClaims = func(_ *oidcClaims, _ *oidc.IDToken) error {
			return fmt.Errorf("test error")
		}
	}

	return token, nil
}

func init() {
	// *oidcIssuer = oidcServer.URL
	oidcWK.Issuer = oidcServer.URL + oidcWK.Issuer
	oidcWK.TokenEndpoint = oidcServer.URL + oidcWK.TokenEndpoint
	oidcWK.AuthorizationEndpoint = oidcServer.URL + oidcWK.AuthorizationEndpoint
}

func TestOIDCSetup(t *testing.T) {
	assert.Contains(t, oidcSetup("ftp://localhost").Error(), "unsupported protocol scheme")
}

func TestOIDCSuccess(t *testing.T) {
	mock := &oidcMock{}
	oidcConfig = mock
	oidcVerifier = mock

	testflight.WithServer(testMux, func(r *testflight.Requester) {
		request, err := http.NewRequest("GET", "/oidc?state=barbaz&next=localhost/next", nil)
		assert.NoError(t, err)

		vals := map[string]interface{}{"state": "barbaz", "next": oidcServer.URL + "/next"}
		cookieValue, err := securecookie.EncodeMulti(*cookieName, &vals, store.Codecs...)
		assert.NoError(t, err)
		request.AddCookie(&http.Cookie{Name: *cookieName, Value: cookieValue})

		request.Host = *host
		response := r.Do(request)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, "NEXT", response.Body)

		b := strings.NewReader("POSTED")
		request, err = http.NewRequest("POST", oidcServer.URL+"/next", b)
		assert.NoError(t, err)
		request.AddCookie(&http.Cookie{Name: *cookieName, Value: cookieValue})

		request.Host = *host
		resp, err := http.DefaultClient.Do(request)
		assert.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		respBody, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, "NEXT", string(respBody))
	})
}

func TestOIDCVerifyToken(t *testing.T) {
	token := &oauth2.Token{}
	s, err := oidcVerifyToken(context.TODO(), token)
	assert.Empty(t, s)
	assert.Equal(t, "missing ID token", err.Error())
}

func TestOIDCVerifyTokenID(t *testing.T) {
	email, err := oidcVerifyTokenID(context.TODO(), "err")
	assert.Equal(t, "", email)
	assert.Equal(t, http.ErrHijacked, err)

	testErr := fmt.Errorf("test error")
	email, err = oidcVerifyTokenID(context.TODO(), "claimsErr")
	assert.Equal(t, "", email)
	assert.Equal(t, testErr, err)

	email, err = oidcVerifyTokenID(context.TODO(), "rawID")
	assert.Equal(t, "user3@domain3.com", email)
	assert.NoError(t, err)
}
