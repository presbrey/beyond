[![Build Status](https://travis-ci.org/presbrey/beyond.svg?branch=master)](https://travis-ci.org/presbrey/beyond)
[![codecov](https://codecov.io/gh/presbrey/beyond/branch/master/graph/badge.svg)](https://codecov.io/gh/presbrey/beyond)
[![Docker](https://github.com/presbrey/beyond/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/presbrey/beyond/actions/workflows/docker-publish.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/presbrey/beyond)](https://goreportcard.com/report/github.com/presbrey/beyond)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# beyond
Control access to services beyond your perimeter network. Deploy with split-DNS to alleviate VPN in a zero-trust transition. Inspired by Google BeyondCorp research: https://research.google.com/pubs/pub45728.html

## Features
- Authenticate via:
  - OpenID Connect
  - OAuth2 Tokens
  - SAMLv2
- Automate Configuration w/ https://your.json
- Customize Nexthop Learning (via Favorite Ports: 443, 80, ...)
- Supports WebSockets
- Supports GitHub Enterprise
- Supports Private Docker Registry APIs (v2)
- Analytics with ElasticSearch

## Install
```
$ docker pull presbrey/beyond
```
or:
```
$ go get -u -x github.com/presbrey/beyond
```
## Usage
```
$ docker run --rm -p 80:80 presbrey/beyond httpd --help
  -401-code int
    	status to respond when a user needs authentication (default 418)
  -404-message string
    	message to use when backend apps do not respond (default "Please contact the application administrators to setup access.")
  -allowlist-url string
    	URL to site allowlist (eg. https://github.com/myorg/beyond-config/main/raw/allowlist.json)
  -beyond-host string
    	hostname of self (default "beyond.myorg.net")
  -cookie-age int
    	MaxAge setting in seconds (default 21600)
  -cookie-domain string
    	session cookie domain (default ".myorg.net")
  -cookie-key1 string
    	key1 of cookie crypto pair (example: "t8yG1gmeEyeb7pQpw544UeCTyDfPkE6u")
  -cookie-key2 string
    	key2 of cookie crypto pair (example: "Q599vrruZRhLFC144thCRZpyHM7qGDjt")
  -cookie-name string
    	session cookie name (default "beyond")
  -docker-auth-scheme string
    	(only for testing) (default "https")
  -docker-url string
    	when there is only one (legacy option) (default "https://docker.myorg.net")
  -docker-urls string
    	csv of docker server base URLs (default "https://harbor.myorg.net,https://ghcr.myorg.net")
  -error-color string
    	css h1 color for errors (default "#69b342")
  -error-email string
    	address for help (eg. support@mycompany.com)
  -error-plain
    	disable html on error pages
  -federate-access string
    	shared secret, 64 chars, enables federation
  -federate-secret string
    	internal secret, 64 chars
  -fence-url string
    	URL to user fencing config (eg. https://github.com/myorg/beyond-config/main/raw/fence.json)
  -header-prefix string
    	prefix extra headers with this string (default "Beyond")
  -health-path string
    	URL of the health endpoint (default "/healthz/ping")
  -health-reply string
    	response body of the health endpoint (default "ok")
  -home-url string
    	redirect users here from root (default "https://google.com")
  -host-masq string
    	rewrite nexthop hosts (format: from1=to1,from2=to2)
  -http string
    	listen address (default ":80")
  -insecure-skip-verify
    	allow TLS backends without valid certificates
  -learn-dial-timeout duration
    	skip port after this connection timeout (default 5s)
  -learn-http-ports string
    	after HTTPS, try these HTTP ports (csv) (default "80,8080,6000,6060,7000,7070,8000,9000,9200,15672")
  -learn-https-ports string
    	try learning these backend HTTPS ports (csv) (default "443,4443,6443,8443,9443,9090")
  -learn-nexthops
    	set false to require explicit allowlisting (default true)
  -log-elastic string
    	csv of elasticsearch servers
  -log-elastic-interval duration
    	how often to commit bulk updates (default 1s)
  -log-elastic-prefix string
    	insert this on the front of elastic indexes (default "beyond")
  -log-elastic-workers int
    	bulk commit workers (default 3)
  -log-http
    	enable HTTP logging to stdout
  -log-json
    	use json output (logrus)
  -log-xff
    	include X-Forwarded-For in logs (default true)
  -oidc-client-id string
    	OIDC client ID (default "f8b8b020-4ec2-0135-6452-027de1ec0c4e43491")
  -oidc-client-secret string
    	OIDC client secret (default "cxLF74XOeRRFDJbKuJpZAOtL4pVPK1t2XGVrDbe5R")
  -oidc-issuer string
    	OIDC issuer URL provided by IdP (default "https://yourcompany.onelogin.com/oidc")
  -saml-cert-file string
    	SAML SP path to cert.pem (default "example/myservice.cert")
  -saml-entity-id string
    	SAML SP entity ID (blank defaults to beyond-host)
  -saml-key-file string
    	SAML SP path to key.pem (default "example/myservice.key")
  -saml-metadata-url string
    	SAML metadata URL from IdP (blank disables SAML)
  -saml-nameid-format string
    	SAML SP option: {email, persistent, transient, unspecified} (default "email")
  -saml-session-key string
    	SAML attribute to map from session (default "email")
  -saml-sign-requests
    	SAML SP signs authentication requests
  -saml-signature-method string
    	SAML SP option: {sha1, sha256, sha512}
  -server-idle-timeout duration
    	max time to wait for the next request when keep-alives are enabled (default 3m0s)
  -server-read-timeout duration
    	max duration for reading the entire request, including the body (default 1m0s)
  -server-write-timeout duration
    	max duration before timing out writes of the response (default 2m0s)
  -sites-url string
    	URL to allowed sites config (eg. https://github.com/myorg/beyond-config/main/raw/sites.json)
  -token-base string
    	token server URL prefix (eg. https://api.github.com/user)
  -token-graphql string
    	GraphQL URL for auth (eg. https://api.github.com/graphql)
  -token-graphql-query string
    	 (default "{\"query\": \"query { viewer { login }}\"}")
  -websocket-compression
    	allow websocket transport compression (gorilla/experimental)
```
