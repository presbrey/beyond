# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Beyond is a BeyondCorp-inspired authentication proxy that controls access to services beyond your perimeter network. It implements zero-trust security patterns with support for OIDC, OAuth2, and SAML authentication.

## Architecture

### Core Components

- **Authentication Layer**: Supports multiple authentication methods (OIDC, OAuth2, SAML)
  - `oidc.go` - OpenID Connect implementation
  - `saml.go` - SAML authentication handling  
  - `token.go` - OAuth2 token validation
  - `federate.go` - Federation support for cross-domain access

- **Proxy Layer**: HTTP/WebSocket reverse proxy with smart backend discovery
  - `proxy.go` - Core reverse proxy implementation
  - `learn.go` - Automatic backend port discovery
  - `masq.go` - Host rewriting functionality

- **Access Control**: Configuration-driven access management
  - `acl.go` - Access control lists and allowlisting
  - Sites/fence/allowlist configuration via JSON URLs

- **Specialized Handlers**:
  - `docker.go` - Docker registry API compatibility
  - `web.go` - Web UI and error pages
  - `log.go` - ElasticSearch integration for analytics

### Request Flow

1. Incoming requests hit the main handler (`handler.go`)
2. Authentication is verified via session cookies
3. Unauthenticated requests redirect to `/launch` for auth flow
4. Authenticated requests are proxied to backend services
5. Backend ports are learned automatically or from configuration

## Development Commands

### Building

```bash
# Build the main httpd binary
go build ./cmd/httpd

# Install to $GOPATH/bin
go install ./cmd/httpd

# Build with Docker
docker build -t beyond .
```

### Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific test
go test -run TestHandlerPing

# Run tests with verbose output
go test -v ./...
```

### Running

```bash
# Run with minimal configuration (see example/ for configs)
go run cmd/httpd/main.go \
  -beyond-host beyond.example.com \
  -cookie-domain .example.com \
  -cookie-key1 "$(openssl rand -hex 16)" \
  -cookie-key2 "$(openssl rand -hex 16)" \
  -oidc-issuer https://your-idp.com/oidc \
  -oidc-client-id your-client-id \
  -oidc-client-secret your-client-secret

# Run with Docker
docker run --rm -p 80:80 presbrey/beyond httpd [flags]
```

### Code Quality

```bash
# Format code
go fmt ./...

# Run linter (install: go install golang.org/x/lint/golint@latest)
golint ./...

# Vet code
go vet ./...
```

## Key Implementation Notes

- Session management uses Gorilla sessions with secure cookies
- WebSocket support includes optional compression
- Automatic backend discovery tries HTTPS first, then HTTP ports
- ElasticSearch logging is optional but recommended for analytics
- Docker registry support handles authentication for private registries
- Federation allows trust relationships between Beyond instances

## Testing Approach

- Tests use `testflight` for HTTP testing
- Mock services created with `httptest`
- Test utilities in `test_utils.go` provide shared setup
- Integration tests cover full authentication flows
- Unit tests focus on individual components

## Configuration

The service is configured via command-line flags. Key configurations:
- Authentication (OIDC/SAML) credentials and endpoints
- Cookie settings for session management
- Backend discovery and port preferences
- Optional ElasticSearch for logging
- Access control via JSON configuration URLs