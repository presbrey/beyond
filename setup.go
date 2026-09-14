package beyond

import (
	"crypto/tls"
	"flag"
	"net/http"
	"strings"

	"github.com/koding/websocketproxy"
	"github.com/presbrey/beyond/internal/authn"
	"github.com/presbrey/beyond/internal/authz"
	"github.com/presbrey/beyond/internal/docker"
	"github.com/sirupsen/logrus"
)

var (
	debug = flag.Bool("debug", true, "set debug loglevel")

	host = flag.String("beyond-host", "beyond.myorg.net", "hostname of self")

	healthPath  = flag.String("health-path", "/healthz/ping", "URL of the health endpoint")
	healthReply = flag.String("health-reply", "ok", "response body of the health endpoint")

	fouroFourMessage = flag.String("404-message", "Please contact the application administrators to setup access.", "message to use when backend apps do not respond")
	fouroOneCode     = flag.Int("401-code", 418, "status to respond when a user needs authentication")
	headerPrefix     = flag.String("header-prefix", "Beyond", "prefix extra headers with this string")

	skipVerify = flag.Bool("insecure-skip-verify", false, "allow TLS backends without valid certificates")
	wsCompress = flag.Bool("websocket-compression", false, "allow websocket transport compression (gorilla/experimental)")

	tlsConfig = &tls.Config{}
)

// Setup initializes all configured modules
func Setup() error {
	var err error
	if *debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	// setup session management
	err = authn.SetupSession()
	if err != nil {
		return err
	}

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

	dURLs := []string{*docker.DockerBase}
	if len(*docker.DockerURLs) > 0 {
		dURLs = append(dURLs, strings.Split(*docker.DockerURLs, ",")...)
	}
	ghpHosts := map[string]bool{}
	for _, k := range strings.Split(*docker.GHPHost, ",") {
		ghpHosts[k] = true
	}
	docker.SetGHPHosts(ghpHosts)

	err = docker.Setup(dURLs...)
	if err == nil {
		err = authn.FederateSetup()
	}
	if err == nil {
		err = authz.HostsSetup(*authz.HostsCSV)
	}
	if err == nil {
		err = authz.RefreshHosts()
	}
	if err == nil {
		err = logSetup()
	}
	if err == nil {
		err = authn.OIDCSetup(*authn.OIDCIssuer, *host)
	}
	if err == nil {
		err = authn.SAMLSetup(*host)
	}
	if err == nil {
		err = authz.RefreshFence()
	}
	if err == nil {
		err = authz.RefreshSites()
	}
	if err == nil {
		err = authz.RefreshAllowlist()
	}
	if err == nil {
		err = reproxy()
	}
	return err
}
