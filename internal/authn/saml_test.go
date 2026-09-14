package authn

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/stretchr/testify/require"
)

type testSAMLSession struct{ user string }

func (s testSAMLSession) GetAttributes() samlsp.Attributes {
	return samlsp.Attributes{"email": {s.user}}
}

type testSAMLProvider struct {
	user    string
	deleted bool
}

func (p *testSAMLProvider) CreateSession(http.ResponseWriter, *http.Request, *saml.Assertion) error {
	return nil
}
func (p *testSAMLProvider) DeleteSession(http.ResponseWriter, *http.Request) error {
	p.deleted = true
	return nil
}
func (p *testSAMLProvider) GetSession(*http.Request) (samlsp.Session, error) {
	return testSAMLSession{p.user}, nil
}

func TestSAMLFilterPersistsLogin(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "new-cookie", true: "existing-cookie"}[existing], func(t *testing.T) {
			preserveSessionConfig(t)
			*CookieKey = strings.Repeat("ab", 32)
			require.NoError(t, SetupSession())
			previous := samlSP
			t.Cleanup(func() { samlSP = previous })
			provider := &testSAMLProvider{user: "user@example.com"}
			samlSP = &samlsp.Middleware{Session: provider}
			request := httptest.NewRequest("GET", "https://auth.example/launch", nil)
			if existing {
				session := store.New(*CookieName)
				session.Values["next"] = "https://app.example/"
				response := httptest.NewRecorder()
				require.NoError(t, session.Save(response))
				request.AddCookie(response.Result().Cookies()[0])
			}
			response := httptest.NewRecorder()
			authenticated, err := SAMLFilter(response, request, nil, *CookieName)
			require.NoError(t, err)
			require.True(t, authenticated)
			require.True(t, provider.deleted)
			cookies := response.Result().Cookies()
			require.Len(t, cookies, 1)
			request = httptest.NewRequest("GET", "https://app.example/", nil)
			request.AddCookie(cookies[0])
			session, err := store.Get(request, *CookieName)
			require.NoError(t, err)
			require.Equal(t, "user@example.com", session.Values["user"])
			if existing {
				require.Equal(t, "https://app.example/", session.Values["next"])
			}
		})
	}
}

func TestSAMLFilterSaveFailureRetainsSAMLSession(t *testing.T) {
	preserveSessionConfig(t)
	*CookieKey = strings.Repeat("ab", 32)
	require.NoError(t, SetupSession())
	previous := samlSP
	t.Cleanup(func() { samlSP = previous })
	provider := &testSAMLProvider{user: strings.Repeat("x", 5000)}
	samlSP = &samlsp.Middleware{Session: provider}
	authenticated, err := SAMLFilter(httptest.NewRecorder(), httptest.NewRequest("GET", "https://auth.example/launch", nil), nil, *CookieName)
	require.Error(t, err)
	require.False(t, authenticated)
	require.False(t, provider.deleted)
}
