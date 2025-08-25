# Beyond - A Go-based Zero-Trust Reverse Proxy

## Project Overview

This project, "beyond," is a reverse proxy written in Go. It's designed to control access to services beyond a perimeter network, inspired by Google's BeyondCorp research. It helps organizations transition to a zero-trust security model, alleviating the need for a traditional VPN.

The application authenticates users via OpenID Connect (OIDC), SAML, or OAuth2 tokens. It can be configured through command-line flags or by providing URLs to JSON configuration files. It also supports WebSocket proxying, private Docker registries, and logging to Elasticsearch.

**Key Technologies:**

*   **Go:** The primary programming language.
*   **OpenID Connect (OIDC):** For modern authentication.
*   **SAML:** For enterprise federation.
*   **OAuth2:** For token-based authentication.
*   **WebSockets:** For real-time communication.
*   **Docker:** For containerized deployment.
*   **Elasticsearch:** For analytics and logging.

**Architecture:**

The application is a single binary that runs as a web server. It's configured at startup and uses a variety of packages to handle different authentication schemes and proxying logic. The main entry point is in `cmd/httpd/main.go`, which sets up and runs an HTTP server. The core logic for configuration and request handling is in the `beyond` package.

## Building and Running

### Building from Source

To build the project from source, you'll need a Go development environment.

```bash
go get -u -x github.com/presbrey/beyond
```

### Running with Docker

The recommended way to run "beyond" is with Docker.

```bash
docker pull presbrey/beyond
```

**Example Usage:**

Here's a basic example of how to run "beyond" with OIDC authentication:

```bash
docker run --rm -p 80:80 presbrey/beyond httpd \
  -beyond-host beyond.example.com \
  -cookie-domain .example.com \
  -oidc-issuer https://your-idp.com/oidc \
  -oidc-client-id your-client-id \
  -oidc-client-secret your-client-secret
```

For more advanced configurations, including SAML, access control, and Docker registry support, refer to the `README.md` file.

### Testing

To run the tests for this project:

```bash
go test ./...
```

## Development Conventions

*   **Configuration:** The application is configured primarily through command-line flags. For more complex configurations, it can fetch JSON files from URLs.
*   **Logging:** The application uses the Logrus library for logging. By default, it logs to standard output. For production use, it can be configured to log to Elasticsearch.
*   **Dependencies:** The project uses Go modules to manage dependencies. The `go.mod` file lists all the required packages.
*   **Code Style:** The code follows standard Go formatting and conventions.
