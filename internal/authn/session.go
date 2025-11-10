package authn

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"

	"github.com/dghubble/sessions"
)

var (
	CookieAge  = flag.Int("cookie-age", 3600*6, "MaxAge setting in seconds")
	CookieDom  = flag.String("cookie-domain", ".myorg.net", "session cookie domain")
	CookieKey  = flag.String("cookie-key", "", `64-char hex key for cookie encryption (example: "t8yG1gmeEyeb7pQpw544UeCTyDfPkE6uQ599vrruZRhLFC144thCRZpyHM7qGDjt")`)
	CookieName = flag.String("cookie-name", "beyond", "session cookie name")

	store *sessions.CookieStore
)

// Session represents a user session
type Session struct {
	Values map[string]interface{}
	sess   *sessions.Session
}

// SessionStore interface for session management
type SessionStore interface {
	Get(r *http.Request, name string) (*Session, error)
	New(name string) *Session
}

// cookieStoreWrapper wraps sessions.CookieStore to implement SessionStore
type cookieStoreWrapper struct {
	store *sessions.CookieStore
}

func (w *cookieStoreWrapper) Get(r *http.Request, name string) (*Session, error) {
	sess, err := w.store.Get(r, name)
	if err != nil {
		return nil, err
	}
	return &Session{Values: sess.Values, sess: sess}, nil
}

func (w *cookieStoreWrapper) New(name string) *Session {
	sess := w.store.New(name)
	return &Session{Values: sess.Values, sess: sess}
}

// Save saves the session
func (s *Session) Save(w http.ResponseWriter) error {
	if s == nil || s.sess == nil {
		return fmt.Errorf("session not initialized")
	}
	return GetStore().Save(w, s.sess)
}

// generateRandomKey creates a 32-byte random key encoded as hex string
func generateRandomKey() (string, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// SetupSession initializes the session store
func SetupSession() error {
	if len(*CookieKey) == 0 {
		// Generate random cookie key for single instance deployments
		key, err := generateRandomKey()
		if err != nil {
			return fmt.Errorf("failed to generate cookie key: %v", err)
		}
		*CookieKey = key
	}

	// Validate key length (should be 64 hex chars = 32 bytes)
	if len(*CookieKey) != 64 {
		return fmt.Errorf("cookie key must be exactly 64 hex characters (32 bytes), got %d", len(*CookieKey))
	}

	// setup encrypted cookies - use the key for both authentication and encryption
	keyBytes, err := hex.DecodeString(*CookieKey)
	if err != nil {
		return fmt.Errorf("cookie key must be valid hex: %v", err)
	}
	store = sessions.NewCookieStore(keyBytes, keyBytes)
	store.Config.Domain = *CookieDom
	store.Config.MaxAge = *CookieAge
	store.Config.HTTPOnly = true
	store.Config.SameSite = http.SameSiteNoneMode
	store.Config.Secure = true

	return nil
}

// GetStore returns the global session store
func GetStore() *sessions.CookieStore {
	return store
}

// GetSession retrieves a session from the request
func GetSession(r *http.Request, name string) (*sessions.Session, error) {
	session, err := store.Get(r, name)
	if err != nil {
		session = store.New(name)
	}
	return session, nil
}

// NewSession creates a new session
func NewSession(name string) *sessions.Session {
	return store.New(name)
}
