package beyond

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"strings"

	"github.com/dghubble/sessions"
	"github.com/koding/websocketproxy"
	"github.com/sirupsen/logrus"
)

var (
	debug = flag.Bool("debug", true, "set debug loglevel")

	host = flag.String("beyond-host", "beyond.myorg.net", "hostname of self")

	healthPath  = flag.String("health-path", "/healthz/ping", "URL of the health endpoint")
	healthReply = flag.String("health-reply", "ok", "response body of the health endpoint")

	cookieAge  = flag.Int("cookie-age", 3600*6, "MaxAge setting in seconds")
	cookieDom  = flag.String("cookie-domain", ".myorg.net", "session cookie domain")
	cookieKey  = flag.String("cookie-key", "", `64-char hex key for cookie encryption (example: "t8yG1gmeEyeb7pQpw544UeCTyDfPkE6uQ599vrruZRhLFC144thCRZpyHM7qGDjt")`)
	cookieName = flag.String("cookie-name", "beyond", "session cookie name")

	fouroFourMessage = flag.String("404-message", "Please contact the application administrators to setup access.", "message to use when backend apps do not respond")
	fouroOneCode     = flag.Int("401-code", 418, "status to respond when a user needs authentication")
	headerPrefix     = flag.String("header-prefix", "Beyond", "prefix extra headers with this string")

	skipVerify = flag.Bool("insecure-skip-verify", false, "allow TLS backends without valid certificates")
	wsCompress = flag.Bool("websocket-compression", false, "allow websocket transport compression (gorilla/experimental)")

	store *sessions.CookieStore

	tlsConfig = &tls.Config{}
)

// generateRandomKey creates a 32-byte random key encoded as hex string
func generateRandomKey() (string, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// Setup initializes all configured modules
func Setup() error {
	if *debug {
		logrus.SetLevel(logrus.DebugLevel)
	}
	if len(*cookieKey) == 0 {
		// Generate random cookie key for single instance deployments
		key, err := generateRandomKey()
		if err != nil {
			return fmt.Errorf("failed to generate cookie key: %v", err)
		}
		*cookieKey = key
		
		logrus.Warn("No cookie key provided, generated random key for this session:")
		logrus.Warnf("  -cookie-key %s", *cookieKey)
		logrus.Warn("IMPORTANT: Sessions will not persist across restarts. Set explicit key for production use.")
	}

	// Validate key length (should be 64 hex chars = 32 bytes)
	if len(*cookieKey) != 64 {
		return fmt.Errorf("cookie key must be exactly 64 hex characters (32 bytes), got %d", len(*cookieKey))
	}

	// setup encrypted cookies - use the key for both authentication and encryption
	keyBytes, err := hex.DecodeString(*cookieKey)
	if err != nil {
		return fmt.Errorf("cookie key must be valid hex: %v", err)
	}
	store = sessions.NewCookieStore(keyBytes, keyBytes)
	store.Config.Domain = *cookieDom
	store.Config.MaxAge = *cookieAge
	store.Config.HTTPOnly = true
	store.Config.SameSite = http.SameSiteNoneMode
	store.Config.Secure = true

	// setup backend encryption
	tlsConfig.InsecureSkipVerify = *skipVerify
	http.DefaultTransport = &http.Transport{TLSClientConfig: tlsConfig}

	// setup websockets
	if websocketproxy.DefaultDialer.TLSClientConfig == nil {
		websocketproxy.DefaultDialer.TLSClientConfig = &tls.Config{}
	}
	websocketproxy.DefaultDialer.TLSClientConfig.InsecureSkipVerify = *skipVerify
	websocketproxy.DefaultDialer.EnableCompression = *wsCompress
	websocketproxy.DefaultUpgrader.EnableCompression = *wsCompress
	websocketproxy.DefaultUpgrader.CheckOrigin = websocketproxyCheckOrigin

	dURLs := []string{*dockerBase}
	if len(*dockerURLs) > 0 {
		dURLs = append(dURLs, strings.Split(*dockerURLs, ",")...)
	}
	for _, k := range strings.Split(*ghpHost, ",") {
		ghpHosts[k] = true
	}

	err = dockerSetup(dURLs...)
	if err == nil {
		err = federateSetup()
	}
	if err == nil {
		err = hostsSetup(*hostsCSV)
	}
	if err == nil {
		err = refreshHosts()
	}
	if err == nil {
		err = logSetup()
	}
	if err == nil {
		err = oidcSetup(*oidcIssuer)
	}
	if err == nil {
		err = samlSetup()
	}
	if err == nil {
		err = refreshFence()
	}
	if err == nil {
		err = refreshSites()
	}
	if err == nil {
		err = refreshAllowlist()
	}
	if err == nil {
		err = reproxy()
	}
	return err
}
