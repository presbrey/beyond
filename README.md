[![Go](https://github.com/presbrey/beyond/actions/workflows/go.yml/badge.svg)](https://github.com/presbrey/beyond/actions/workflows/go.yml)
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

### Example Configurations

#### Basic OIDC Setup
```bash
docker run --rm -p 80:80 presbrey/beyond httpd \
  -beyond-host beyond.example.com \
  -cookie-domain .example.com \
  -oidc-issuer https://your-idp.com/oidc \
  -oidc-client-id your-client-id \
  -oidc-client-secret your-client-secret
```

#### OIDC with Access Control
```bash
docker run --rm -p 80:80 presbrey/beyond httpd \
  -beyond-host beyond.example.com \
  -cookie-domain .example.com \
  -oidc-issuer https://accounts.google.com \
  -oidc-client-id your-google-client-id \
  -oidc-client-secret your-google-client-secret \
  -allowlist-url https://raw.githubusercontent.com/yourorg/config/main/allowlist.json \
  -fence-url https://raw.githubusercontent.com/yourorg/config/main/fence.json \
  -sites-url https://raw.githubusercontent.com/yourorg/config/main/sites.json
```

#### SAML with Docker Registry Support
```bash
docker run --rm -p 80:80 \
  -v /path/to/certs:/certs \
  presbrey/beyond httpd \
  -beyond-host beyond.example.com \
  -cookie-domain .example.com \
  -saml-metadata-url https://your-idp.com/metadata \
  -saml-cert-file /certs/saml.cert \
  -saml-key-file /certs/saml.key \
  -docker-urls https://harbor.example.com,https://ghcr.example.com
```

#### GitHub Enterprise with Token Auth
```bash
docker run --rm -p 80:80 presbrey/beyond httpd \
  -beyond-host beyond.example.com \
  -cookie-domain .example.com \
  -oidc-issuer https://github.example.com \
  -oidc-client-id your-github-app-id \
  -oidc-client-secret your-github-app-secret \
  -token-base https://api.github.example.com/user \
  -docker-urls https://docker.pkg.github.example.com
```

#### Production with Elasticsearch Logging
```bash
docker run --rm -p 80:80 presbrey/beyond httpd \
  -beyond-host beyond.example.com \
  -cookie-domain .example.com \
  -oidc-issuer https://login.example.com \
  -oidc-client-id production-client-id \
  -oidc-client-secret production-client-secret \
  -allowlist-url https://config.example.com/allowlist.json \
  -fence-url https://config.example.com/fence.json \
  -sites-url https://config.example.com/sites.json \
  -hosts-url https://config.example.com/hosts.json \
  -log-elastic https://elasticsearch.example.com:9200 \
  -log-json \
  -error-email support@example.com
```

### Cookie Key Management

Beyond requires a single cryptographic key for session cookie encryption. You have two options:

#### Option 1: Auto-Generated Key (Development/Testing)
If no cookie key is provided, Beyond will automatically generate a secure random key at startup and log it:
```
WARN[0000] No cookie key provided, generated random key for this session:
WARN[0000]   -cookie-key a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
WARN[0000] IMPORTANT: Sessions will not persist across restarts. Set explicit key for production use.
```

#### Option 2: Explicit Key (Production)
For production deployments, always set an explicit key to maintain session persistence:
```bash
# Generate key once and reuse it
export COOKIE_KEY=$(openssl rand -hex 32)

docker run --rm -p 80:80 presbrey/beyond httpd \
  -cookie-key "$COOKIE_KEY" \
  # ... other parameters
```

### Host Management

Beyond supports rewriting backend hostnames to different values and restricting access to only specific hosts. This is useful for legacy system migrations, internal name mapping, and creating secure host allowlists.

#### Host Rewriting
You can configure host rewriting in two ways:

**Option 1: Command Line**
Replacement values can include protocols and ports for advanced routing:
```bash
docker run --rm -p 80:80 presbrey/beyond httpd \
  -hosts-csv "old-api.example.com=https://new-api.example.com:8443,legacy.corp=http://modern.corp.example.com:8080" \
  # ... other parameters
```

**Option 2: JSON Configuration File**
Create a JSON file with hostname mappings. Replacement values can include protocols and ports:
```json
{
  "old-api.example.com": "new-api.example.com",
  "legacy.mycompany.net": "https://modern.mycompany.net:8443",
  "internal.corp": "http://internal.corp.example.com:8080",
  "secure.app": "https://secure.app.example.com"
}
```

Then reference it:
```bash
docker run --rm -p 80:80 presbrey/beyond httpd \
  -hosts-url https://config.example.com/hosts.json \
  # ... other parameters
```

#### Protocol and Port Support

When replacement values include full URLs (with `http://` or `https://`), Beyond extracts the protocol and port information for backend connections:

- **Simple hostname replacement**: `"old.example.com": "new.example.com"` - preserves original protocol and port
- **Protocol specification**: `"legacy.api": "https://modern.api"` - forces HTTPS connection to backend
- **Port specification**: `"internal.app": "http://internal.app:8080"` - connects to specific port
- **Full URL**: `"old.secure": "https://new.secure:9443"` - specifies both protocol and port

Subdomain matching is preserved: if `api.legacy.com` maps to `https://api.modern.com:8443`, then `service.api.legacy.com` becomes `service.api.modern.com` with HTTPS on port 8443.

#### Host Allowlist (hosts-only mode)
Use the `-hosts-only` flag to restrict access to only hosts defined in your host mappings:

```bash
docker run --rm -p 80:80 presbrey/beyond httpd \
  -hosts-url https://config.example.com/hosts.json \
  -hosts-only \
  # ... other parameters
```

When `hosts-only` is enabled:
- Only hosts in the mapping (from `-hosts-csv` or `-hosts-url`) are allowed
- Requests to unmapped hosts return 403 "Host not allowed"
- Subdomain matching works (e.g., `api.example.com` matches `example.com`)

Both command-line and URL mappings can be used together - they are merged at startup.

### Command Line Options
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
  -cookie-key string
    	64-char hex key for cookie encryption (example: "t8yG1gmeEyeb7pQpw544UeCTyDfPkE6uQ599vrruZRhLFC144thCRZpyHM7qGDjt")
  -cookie-name string
    	session cookie name (default "beyond")
  -debug
    	set debug loglevel (default true)
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
  -ghp-hosts string
    	CSV of github packages domains (default "ghp.myorg.net")
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
    	skip port after this connection timeout (default 8s)
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
    	OIDC issuer URL provided by IdP (default "https://accounts.google.com")
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
