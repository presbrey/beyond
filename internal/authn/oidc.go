package authn

import (
	"context"
	"flag"
	"fmt"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

var (
	OIDCIssuer       = flag.String("oidc-issuer", "https://accounts.google.com", "OIDC issuer URL provided by IdP")
	OIDCClientID     = flag.String("oidc-client-id", "f8b8b020-4ec2-0135-6452-027de1ec0c4e43491", "OIDC client ID")
	OIDCClientSecret = flag.String("oidc-client-secret", "cxLF74XOeRRFDJbKuJpZAOtL4pVPK1t2XGVrDbe5R", "OIDC client secret")

	OIDCConfig   OIDCConfigI
	OIDCVerifier OIDCVerifierI

	GetOIDCClaims = parseClaims
)

// OIDCClaims represents OIDC token claims
type OIDCClaims struct {
	Email string `json:"email"`
}

// OIDCConfigI is the interface for OIDC configuration
type OIDCConfigI interface {
	AuthCodeURL(string, ...oauth2.AuthCodeOption) string
	Exchange(context.Context, string) (*oauth2.Token, error)
}

type oauth2ConfigWrapper struct {
	*oauth2.Config
}

func (w *oauth2ConfigWrapper) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return w.Config.AuthCodeURL(state, opts...)
}

func (w *oauth2ConfigWrapper) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return w.Config.Exchange(ctx, code)
}

// OIDCVerifierI is the interface for OIDC token verification
type OIDCVerifierI interface {
	Verify(context.Context, string) (*oidc.IDToken, error)
}

// OIDCSetup initializes the OIDC provider
func OIDCSetup(issuer, host string) error {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return err
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := &oauth2.Config{
		ClientID:     *OIDCClientID,
		ClientSecret: *OIDCClientSecret,
		RedirectURL:  "https://" + host + "/oidc",

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}

	OIDCVerifier = provider.Verifier(&oidc.Config{
		ClientID: oauth2Config.ClientID,
	})
	OIDCConfig = &oauth2ConfigWrapper{oauth2Config}
	return nil
}

// OIDCVerify verifies an OIDC authorization code and returns the user email
func OIDCVerify(code string) (string, error) {
	ctx := context.Background()
	token, err := OIDCConfig.Exchange(ctx, code)
	if err != nil {
		return "", err
	}
	return OIDCVerifyToken(ctx, token)
}

// OIDCVerifyToken verifies an OAuth2 token and extracts the user email
func OIDCVerifyToken(ctx context.Context, token *oauth2.Token) (string, error) {
	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		return "", fmt.Errorf("missing ID token")
	}
	return OIDCVerifyTokenID(ctx, rawID)
}

// OIDCVerifyTokenID verifies an OIDC ID token and extracts the user email
func OIDCVerifyTokenID(ctx context.Context, rawID string) (string, error) {
	var err error
	tokenID, err := OIDCVerifier.Verify(ctx, rawID)
	if err != nil {
		return "", err
	}
	claims := new(OIDCClaims)
	err = GetOIDCClaims(claims, tokenID)
	if err != nil {
		return "", err
	}
	return claims.Email, nil
}

func parseClaims(claims *OIDCClaims, tokenID *oidc.IDToken) error {
	return tokenID.Claims(claims)
}

// OIDCAuthCodeURL returns the OIDC authorization URL
func OIDCAuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return OIDCConfig.AuthCodeURL(state, opts...)
}
