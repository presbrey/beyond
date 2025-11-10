package beyond

import (
	"flag"
	"fmt"
	"net/http"

	"github.com/presbrey/beyond/internal/authn"
	"github.com/presbrey/beyond/internal/docker"
)

var (
	homeURL = flag.String("home-url", "https://google.com", "redirect users here from root")
)

// NewMux mounts all configured web handlers
func NewMux() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc(*healthPath, func(rw http.ResponseWriter, r *http.Request) {
		fmt.Fprint(rw, *healthReply)
	})

	mux.HandleFunc(*host+"/federate", func(w http.ResponseWriter, r *http.Request) {
		authn.Federate(w, r, *authn.CookieName, login)
	})
	mux.HandleFunc(*host+"/federate/verify", authn.FederateVerify)

	mux.HandleFunc(*host+"/launch", handleLaunch)
	mux.HandleFunc(*host+"/oidc", handleOIDC)
	if authn.SAMLMiddleware() != nil {
		mux.HandleFunc(*host+"/saml/", authn.SAMLMiddleware().ServeHTTP)
	}
	mux.Handle(*host+"/", http.RedirectHandler(*homeURL, http.StatusTemporaryRedirect))

	for _, ds := range docker.GetServers() {
		ds.RegisterHandlers(mux)
	}

	// Set docker package dependencies
	docker.Debug = debug
	docker.LogRoundtrip = logRoundtrip
	docker.Handler = handler

	mux.HandleFunc("/", handler)

	return mux
}
