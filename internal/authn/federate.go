package authn

import (
	"encoding/json"
	"flag"
	"net/http"

	"github.com/gorilla/securecookie"
)

var (
	FederateAccessKey = flag.String("federate-access", "", "shared secret, 64 chars, enables federation")
	FederateSecretKey = flag.String("federate-secret", "", "internal secret, 64 chars")

	federateAccessCodec []securecookie.Codec
	federateSecretCodec []securecookie.Codec
)

// FederateSetup initializes the federation codecs
func FederateSetup() error {
	if *FederateAccessKey == "" {
		return nil
	}

	federateAccessCodec = securecookie.CodecsFromPairs([]byte(*FederateAccessKey)[0:31], []byte(*FederateAccessKey)[32:64])
	federateSecretCodec = securecookie.CodecsFromPairs([]byte(*FederateSecretKey)[0:31], []byte(*FederateSecretKey)[32:64])
	return nil
}

// Federate handles federation requests
func Federate(w http.ResponseWriter, r *http.Request, cookieName string, loginHandler func(http.ResponseWriter, *http.Request)) {
	setCacheControl(w)

	// authenticate relying party
	next := r.URL.Query().Get("next")
	err := securecookie.DecodeMulti("next", next, &next, federateAccessCodec...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// authenticate end user
	session, err := GetSession(r, cookieName)
	if err != nil {
		session = NewSession(cookieName)
	}
	user, _ := session.Values["user"].(string)

	// 401
	if user == "" {
		loginHandler(w, r)
		return
	}

	// issue token
	token, err := securecookie.EncodeMulti("user", user, federateSecretCodec...)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// 302
	http.Redirect(w, r, next+token, http.StatusFound)
}

// FederateVerify verifies a federation token
func FederateVerify(w http.ResponseWriter, r *http.Request) {
	// authenticate relying party
	token := r.URL.Query().Get("token")
	err := securecookie.DecodeMulti("user", token, &token, federateSecretCodec...)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	v := map[string]string{"email": token}
	json.NewEncoder(w).Encode(v)
}

// EncodeFederateNext encodes a next URL for federation
func EncodeFederateNext(next string) (string, error) {
	return securecookie.EncodeMulti("next", next, federateAccessCodec...)
}

func setCacheControl(w http.ResponseWriter) {
	if w == nil {
		return
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
}
