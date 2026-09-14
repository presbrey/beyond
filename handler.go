package beyond

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/presbrey/beyond/internal/authn"
	"github.com/presbrey/beyond/internal/authz"
	"golang.org/x/oauth2"
)

func handleLaunch(w http.ResponseWriter, r *http.Request) {
	setCacheControl(w)
	session, err := authn.GetSession(r, *authn.CookieName)
	if err != nil {
		session = authn.NewSession(*authn.CookieName)
	}
	samlAuthenticated, err := authn.SAMLFilter(w, r, nil, *authn.CookieName)
	if err != nil {
		errorHandler(w, http.StatusInternalServerError, "Unable to save login session")
		return
	}
	if samlAuthenticated {
		next, _ := session.Values["next"].(string)
		jsRedirect(w, next)
		return
	}

	session.Values["next"] = r.URL.Query().Get("next")
	state, _ := authn.RandHex32()
	session.Values["state"] = state
	if err := session.Save(w); err != nil {
		errorHandler(w, http.StatusInternalServerError, "Unable to save login session")
		return
	}

	if *authn.SAMLIDP == "" {
		next := authn.OIDCAuthCodeURL(state, oauth2.AccessTypeOffline)
		jsRedirect(w, next)
	} else {
		authn.SAMLHandleStartAuthFlow(w, r)
	}
}

func handleOIDC(w http.ResponseWriter, r *http.Request) {
	setCacheControl(w)

	if r.URL.Query().Get("error") != "" {
		errorQuery(w, r)
		return
	}

	session, err := authn.GetSession(r, *authn.CookieName)
	if err != nil {
		errorHandler(w, 400, err.Error())
		return
	}
	if state, ok := session.Values["state"].(string); !ok || state == "" || state != r.URL.Query().Get("state") {
		errorHandler(w, 403, "Invalid Browser State")
		return
	}
	email, err := authn.OIDCVerify(r.URL.Query().Get("code"))
	if err != nil {
		errorHandler(w, 401, err.Error())
		return
	}
	session.Values["user"] = email
	next, _ := session.Values["next"].(string)
	session.Values["next"] = ""
	session.Values["state"] = ""
	if err := session.Save(w); err != nil {
		errorHandler(w, http.StatusInternalServerError, "Unable to save login session")
		return
	}

	http.Redirect(w, r, next, http.StatusFound)
}

func handler(w http.ResponseWriter, r *http.Request) {
	// check for cookie authentication
	session, err := authn.GetSession(r, *authn.CookieName)
	if err != nil {
		session = authn.NewSession(*authn.CookieName)
	}
	user, _ := session.Values["user"].(string)

	// check for oauth2 token
	if user == "" {
		user = authn.TokenAuth(r)
	}
	if user != "" {
		r.Header.Set(*headerPrefix+"-User", user)
	}

	// check host-only restriction
	if !authz.HostAllowed(r.Host) {
		errorHandler(w, 403, "Host not allowed")
		return
	}

	// apply allowlist within the configured host restriction
	if authz.Allowlisted(r) {
		nexthop(w, r)
		return
	}

	// force login
	if user == "" {
		login(w, r)
		return
	}

	// apply fence
	if authz.Deny(r, user) {
		errorHandler(w, 403, "Access Denied")
		return
	}

	// allow
	nexthop(w, r)
}

func login(w http.ResponseWriter, r *http.Request) {
	if w == nil {
		return
	}

	setCacheControl(w)
	w.WriteHeader(*fouroOneCode)

	// short-circuit WS+AJAX
	if r.Header.Get("Upgrade") != "" || r.Header.Get("X-Requested-With") != "" {
		return
	}

	jsRedirect(w, "https://"+*host+"/launch?next="+url.QueryEscape("https://"+r.Host+r.RequestURI))
}

func jsRedirect(w http.ResponseWriter, next string) {
	if w == nil {
		return
	}

	// hack to guarantee interactive session
	w.Header().Set("Content-Type", "text/html")
	parsed, err := url.Parse(next)
	if err != nil || (parsed.Scheme != "" && parsed.Scheme != "http" && parsed.Scheme != "https") {
		next = "/"
	}
	encoded, _ := json.Marshal(next)
	fmt.Fprintf(w, `
<script type="text/javascript">
window.location.replace(%s);
</script>
`, encoded)
}

func setCacheControl(w http.ResponseWriter) {
	if w == nil {
		return
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
}
