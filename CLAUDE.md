# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Beyond is a zero-trust access proxy inspired by Google BeyondCorp. It controls access to services beyond your perimeter network using authentication (OIDC, OAuth2, SAML) and fine-grained access control policies.

## Build and Test Commands

```bash
# Build all packages
go build -v ./...

# Build the main binary
go build -v ./cmd/httpd

# Run all tests
go test -v ./...

# Run tests for a specific package
go test -v ./[package_name]_test.go

# Run a single test
go test -v -run TestFunctionName
```

## Architecture Overview

### Request Flow
1. **Entry Point**: `cmd/httpd/main.go` creates HTTP server with `beyond.NewMux()` handler
2. **Setup**: `setup.go:Setup()` initializes all modules (OIDC, SAML, ACLs, logging, etc.)
3. **Routing**: `web.go:NewMux()` mounts handlers for health, auth, federation, Docker registry, and default proxy
4. **Main Handler**: `handler.go:handler()` processes each request through this flow:
   - Check session cookie authentication
   - Check OAuth2 token authentication
   - Apply allowlist (bypass auth for allowlisted paths/hosts)
   - Check host-only restriction (if `-hosts-only` enabled)
   - Force login if unauthenticated
   - Apply fence (user-specific access restrictions)
   - Forward to backend via `nexthop()`

### Backend Connection Flow (`proxy.go`)
1. **Host Rewriting**: `hostRewriteDetailed()` translates incoming host to backend target
   - Supports protocol switching (http/https)
   - Supports port remapping
   - Preserves subdomains during translation
2. **Nexthop Learning**: If backend not cached and `-learn-nexthops=true`:
   - `learn.go:learn()` probes common HTTPS ports (443, 4443, 6443, 8443, 9443, 9090)
   - Then tries HTTP ports (80, 8080, etc.)
   - Caches successful backends in `hostProxy` sync.Map
3. **Proxying**: Creates reverse proxy or WebSocket proxy depending on Upgrade header

### Authentication Flow
- **OIDC** (`oidc.go`): `/launch` redirects to IdP, `/oidc` handles callback and sets session
- **SAML** (`saml.go`): `/launch` initiates SAML flow, `/saml/*` handles assertions
- **Token Auth** (`token.go`): Validates bearer tokens or query params against configured endpoints

### Access Control Layers
1. **Allowlist** (`acl.go`): Bypass auth for specific host, host:method, or path patterns
2. **Host Filtering** (`masq.go`): When `-hosts-only` is set, only allow configured hosts
3. **Fence** (`acl.go`): User-specific restrictions mapping users to allowed site zones
4. **Sites** (`acl.go`): Named zones containing lists of allowed backend URLs

### Special Features
- **Docker Registry** (`docker.go`): Intercepts `/v2/` endpoints for registry authentication
- **Federation** (`federate.go`): Allows Beyond instances to trust each other's auth
- **Host Masquerading** (`masq.go`): Rewrites backend hostnames with protocol/port support
- **Elasticsearch Logging** (`log.go`): Bulk commits HTTP logs to configured ES clusters

## Configuration Files

External JSON configuration URLs are supported for:
- **Allowlist** (`-allowlist-url`): `{"host": [...], "host:method": [...], "path": [...]}`
- **Fence** (`-fence-url`): `{"user@example.com": ["zone1", "zone2"]}`
- **Sites** (`-sites-url`): `{"zone1": ["https://app1.example.com", "https://app2.example.com"]}`
- **Hosts** (`-hosts-url`): `{"old.example.com": "https://new.example.com:8443"}`

## Key Implementation Details

### Session Management
- Cookie-based sessions using gorilla/securecookie
- Cookie key auto-generated if not provided (logs warning)
- Sessions store user email, OAuth state, and next URL

### TLS and Backend Trust
- `-insecure-skip-verify` allows untrusted backend certificates
- Applies to both HTTP transport and WebSocket connections
- TLS config shared via `tlsConfig` global variable

### WebSocket Handling
- Detects `Upgrade: websocket` header in `proxy.go:nexthop()`
- Converts http/https schemes to ws/wss in `http2ws()`
- Uses koding/websocketproxy with custom director for headers

### Error Handling
- Custom error pages with configurable color and support email
- `-401-code` defaults to 418 (teapot) to trigger browser auth properly
- Health check endpoint at `/healthz/ping` (configurable)

## Testing Patterns

Tests use standard Go testing with:
- `httptest` for HTTP server testing
- Table-driven tests for multiple scenarios
- Mock authentication for handler tests
- Temporary test servers for integration tests
