# v1.9.0 — Host management and authentication updates

This release brings the development work on main together with the security and
dependency maintenance changes from v1.8.11.

## Changes

- Add host mappings from `-hosts-csv` and `-hosts-url`, including HTTP/HTTPS and
  backend port selection, and `-hosts-only` restrictions.
- Match hosts at DNS label boundaries, prefer the most specific mapping, and
  preserve subdomains in HTTP and WebSocket backend URLs.
- Cache proxies by their complete configured target so services on different
  backend ports cannot reuse each other's proxy.
- Keep host restrictions active for authentication-allowlisted requests.
- Separate authentication, authorization, and registry support into internal
  packages; fix SAML login session persistence and cookie-save error handling.
- Add the single `-cookie-key` option and automatic temporary key generation.
- Retain `-cookie-key1`, `-cookie-key2`, and `-host-masq` for existing deployments.
- Reject empty OIDC state values and safely encode JavaScript login redirects.
- Update Elasticsearch log identifiers to use UUIDs.
- Include dependency updates and Go 1.26 builds from the maintenance release.
- Remove the stale checked-in macOS executable; install from source or use the
  published container image.
- Replace external test services with local fixtures and add regression tests for
  cookie compatibility, SAML session persistence, host restrictions, and routing.

## Upgrading

Existing deployments can retain their cookie key pair and cookie settings; no
forced session migration is required. The legacy keys are raw strings. The new
`-cookie-key` option takes 64 hexadecimal characters. Do not combine the two
configuration styles. Switching keys invalidates existing cookies. Automatically
generated keys are temporary and must be replaced with persistent configuration
for sessions to survive restarts or work across multiple instances.

`-host-masq` remains an alias for `-hosts-csv`. Host matching now requires a full
DNS label boundary. With `-hosts-only`, even authentication-allowlisted proxy
requests must target a configured host.

Source builds require Go 1.26 or newer. Go consumers should use the module path
`github.com/presbrey/beyond` (the v1.8 maintenance line retains
`github.com/cogolabs/beyond`).

Container: `ghcr.io/presbrey/beyond:v1.9.0`.

## Validation

- Build, vet, module verification, and uncached race tests pass locally.
- Race tests and govulncheck also pass in the container on Go 1.26.8.
- govulncheck reports no reachable vulnerabilities and no vulnerabilities in
  imported packages. The unused OpenPGP package in golang.org/x/crypto has the
  module-level advisory GO-2026-5932; Beyond does not import it.
- Container startup and health checks pass for both legacy and single-key
  configurations, using a local OIDC discovery fixture.
- A local WebSocket echo test passes through the authenticated proxy and host
  mapping. The inherited external WebSocket echo tests remain skipped.
- The SAML regression tests cover session persistence and save failures with
  local session fixtures; they do not replace a live identity-provider test.
