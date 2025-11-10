package authn

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"net/http"
	"net/url"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/pkg/errors"

	dsig "github.com/russellhaering/goxmldsig"
)

var (
	SAMLCert = flag.String("saml-cert-file", "example/myservice.cert", "SAML SP path to cert.pem")
	SAMLKey  = flag.String("saml-key-file", "example/myservice.key", "SAML SP path to key.pem")

	SAMLID  = flag.String("saml-entity-id", "", "SAML SP entity ID (blank defaults to beyond-host)")
	SAMLIDP = flag.String("saml-metadata-url", "", "SAML metadata URL from IdP (blank disables SAML)")

	SAMLNIDF = flag.String("saml-nameid-format", "email", "SAML SP option: {email, persistent, transient, unspecified}")
	SAMLAttr = flag.String("saml-session-key", "email", "SAML attribute to map from session")

	SAMLSignRequests = flag.Bool("saml-sign-requests", false, "SAML SP signs authentication requests")
	SAMLSignMethod   = flag.String("saml-signature-method", "", "SAML SP option: {sha1, sha256, sha512}")

	samlSP *samlsp.Middleware
)

// SAMLSetup initializes the SAML service provider
func SAMLSetup(host string) error {
	if *SAMLIDP == "" {
		return nil
	}
	if *SAMLID == "" {
		*SAMLID = host
	}

	keyPair, err := tls.LoadX509KeyPair(*SAMLCert, *SAMLKey)
	if err != nil {
		return err
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return err
	}

	idpMetadataURL, err := url.Parse(*SAMLIDP)
	if err != nil {
		return err
	}
	idpMetadata, err := samlsp.FetchMetadata(
		context.Background(), http.DefaultClient,
		*idpMetadataURL)
	if err != nil {
		return err
	}

	rootURL, _ := url.Parse("https://" + host)
	samlSP, err = samlsp.New(samlsp.Options{
		EntityID:    *SAMLID,
		SignRequest: *SAMLSignRequests,
		URL:         *rootURL,

		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),

		AllowIDPInitiated: true,
	})
	if err != nil {
		return err
	}

	switch *SAMLNIDF {
	case "email":
		samlSP.ServiceProvider.AuthnNameIDFormat = saml.EmailAddressNameIDFormat
	case "persistent":
		samlSP.ServiceProvider.AuthnNameIDFormat = saml.PersistentNameIDFormat
	case "transient":
		samlSP.ServiceProvider.AuthnNameIDFormat = saml.TransientNameIDFormat
	case "unspecified":
		samlSP.ServiceProvider.AuthnNameIDFormat = saml.UnspecifiedNameIDFormat
	case "":
	default:
		return errors.Errorf("invalid saml-nameid-format: \"%s\"", *SAMLNIDF)
	}

	switch *SAMLSignMethod {
	case "sha1":
		samlSP.ServiceProvider.SignatureMethod = dsig.RSASHA1SignatureMethod
	case "sha256":
		samlSP.ServiceProvider.SignatureMethod = dsig.RSASHA256SignatureMethod
	case "sha512":
		samlSP.ServiceProvider.SignatureMethod = dsig.RSASHA512SignatureMethod
	case "":
	default:
		return errors.Errorf("invalid saml-signature-method: \"%s\"", *SAMLSignMethod)
	}
	return nil
}

// SAMLFilter processes SAML authentication and sets the user session
func SAMLFilter(w http.ResponseWriter, r *http.Request, sessionStore SessionStore, cookieName string) bool {
	if samlSP == nil {
		return false
	}

	samlSession, _ := samlSP.Session.GetSession(r)
	if _, ok := samlSession.(samlsp.SessionWithAttributes); !ok {
		// sessions without mappings will redirect infinitely
		return false
	}
	samlAttributes := samlSession.(samlsp.SessionWithAttributes).GetAttributes()
	user := samlAttributes.Get(*SAMLAttr)
	if user == "" {
		// nil IdP assertion unlikely
		return false
	}

	session, err := sessionStore.Get(r, cookieName)
	if err != nil {
		session = sessionStore.New(cookieName)
	}
	session.Values["user"] = user
	session.Save(w)
	samlSP.Session.DeleteSession(w, r)
	return true
}

// SAMLMiddleware returns the SAML middleware for handling SAML endpoints
func SAMLMiddleware() *samlsp.Middleware {
	return samlSP
}

// SAMLHandleStartAuthFlow initiates the SAML authentication flow
func SAMLHandleStartAuthFlow(w http.ResponseWriter, r *http.Request) {
	if samlSP != nil {
		samlSP.HandleStartAuthFlow(w, r)
	}
}
