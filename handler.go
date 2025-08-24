package beyond

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
)

func handleLaunch(w http.ResponseWriter, r *http.Request) {
	setCacheControl(w)
	session, err := store.Get(r, *cookieName)
	if err != nil {
		session = store.New(*cookieName)
	}
	if samlSP != nil && samlFilter(w, r) {
		next, _ := session.Values["next"].(string)
		jsRedirect(w, next)
		return
	}

	session.Values["next"] = r.URL.Query().Get("next")
	state, _ := randhex32()
	session.Values["state"] = state
	session.Save(w)

	if *samlIDP == "" {
		next := oidcConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
		jsRedirect(w, next)
	} else {
		samlSP.HandleStartAuthFlow(w, r)
	}
}

func handleOIDC(w http.ResponseWriter, r *http.Request) {
	setCacheControl(w)

	if r.URL.Query().Get("error") != "" {
		errorQuery(w, r)
		return
	}

	session, err := store.Get(r, *cookieName)
	if err != nil {
		errorHandler(w, 400, err.Error())
		return
	}
	if state, ok := session.Values["state"].(string); !ok || state != r.URL.Query().Get("state") {
		errorHandler(w, 403, "Invalid Browser State")
		return
	}
	email, err := oidcVerify(r.URL.Query().Get("code"))
	if err != nil {
		errorHandler(w, 401, err.Error())
		return
	}
	session.Values["user"] = email
	next, _ := session.Values["next"].(string)
	session.Values["next"] = ""
	session.Values["state"] = ""
	session.Save(w)

	http.Redirect(w, r, next, http.StatusFound)
}

func handler(w http.ResponseWriter, r *http.Request) {
	// check for cookie authentication
	session, err := store.Get(r, *cookieName)
	if err != nil {
		session = store.New(*cookieName)
	}
	user, _ := session.Values["user"].(string)

	// check for oauth2 token
	if user == "" {
		user = tokenAuth(r)
	}
	if user != "" {
		r.Header.Set(*headerPrefix+"-User", user)
	}

	// apply allowlist
	if allowlisted(r) {
		nexthop(w, r)
		return
	}

	// check host-only restriction
	if !hostAllowed(r.Host) {
		errorHandler(w, 403, "Host not allowed")
		return
	}

	// force login
	if user == "" {
		login(w, r)
		return
	}

	// apply fence
	if deny(r, user) {
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
	fmt.Fprintf(w, `
<script type="text/javascript">
window.location.replace("%s");
</script>
`, next)
}

func setCacheControl(w http.ResponseWriter) {
	if w == nil {
		return
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
}

func randhex32() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return fmt.Sprintf("%x", b), err
}
