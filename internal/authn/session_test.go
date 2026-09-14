package authn

import (
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/dghubble/sessions"
	"github.com/stretchr/testify/require"
)

func preserveSessionConfig(t *testing.T) {
	t.Helper()
	oldStore, key, key1, key2 := store, *CookieKey, *CookieKey1, *CookieKey2
	t.Cleanup(func() { store = oldStore; *CookieKey, *CookieKey1, *CookieKey2 = key, key1, key2 })
	*CookieKey, *CookieKey1, *CookieKey2 = "", "", ""
}

func TestLegacyCookieCompatibility(t *testing.T) {
	for _, encryptionKey := range []string{"0123456789abcdef", "0123456789abcdef01234567", "0123456789abcdef0123456789abcdef"} {
		t.Run("encryption-key-length-"+strconv.Itoa(len(encryptionKey)), func(t *testing.T) {
			preserveSessionConfig(t)
			*CookieKey1 = "legacy-authentication-key"
			*CookieKey2 = encryptionKey
			// Construct a cookie using exactly the v1.8.11 store configuration.
			oldStore := sessions.NewCookieStore([]byte(*CookieKey1), []byte(encryptionKey))
			oldSession := oldStore.New(*CookieName)
			oldSession.Values["user"] = "existing@example.com"
			oldResponse := httptest.NewRecorder()
			require.NoError(t, oldStore.Save(oldResponse, oldSession))
			require.NoError(t, SetupSession())
			request := httptest.NewRequest("GET", "https://app.example/", nil)
			request.AddCookie(oldResponse.Result().Cookies()[0])
			restored, err := store.Get(request, *CookieName)
			require.NoError(t, err)
			require.Equal(t, "existing@example.com", restored.Values["user"])
			response := httptest.NewRecorder()
			require.NoError(t, restored.Save(response))
			request = httptest.NewRequest("GET", "https://app.example/", nil)
			request.AddCookie(response.Result().Cookies()[0])
			roundTrip, err := oldStore.Get(request, *CookieName)
			require.NoError(t, err)
			require.Equal(t, "existing@example.com", roundTrip.Values["user"])
		})
	}
}

func TestCookieKeyConfigurationErrors(t *testing.T) {
	for _, tc := range []struct{ key, key1, key2 string }{
		{strings.Repeat("ab", 32), "legacy", ""},
		{"", "", "0123456789abcdef"},
		{"", "legacy", "short"},
	} {
		preserveSessionConfig(t)
		*CookieKey, *CookieKey1, *CookieKey2 = tc.key, tc.key1, tc.key2
		require.Error(t, SetupSession())
	}
}
