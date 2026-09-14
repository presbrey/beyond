# v1.8.11 — Security and dependency maintenance

Based on v1.8.10.

This maintenance release updates dependencies while retaining the v1.8.10
configuration and cookie format.

## Included

- Update OIDC, OAuth2, SAML, XML signature validation, JWT, WebSocket, logging,
  and supporting dependencies to the versions recorded in go.mod and go.sum.
- Adapt the existing OAuth2 interface to the updated dependency's Exchange API.
- Build with Go 1.26 or newer; the container and CI use Go 1.26.
- Remove the stale vendor tree so builds use the checked-in module versions.
  Builds need access to the module proxy or a populated module cache. Offline
  builds can regenerate dependencies with `go mod vendor` in advance.
- Replace obsolete external test services with local fixtures and run race tests
  before the container publishing workflow can publish a tag.

## Compatibility

The v1.8.10 module path (`github.com/cogolabs/beyond`), exported application API,
`-cookie-key1`, `-cookie-key2`, and `-host-masq` are retained. Cookie serialization
and the session library version are unchanged. Keep the existing keys and cookie
settings when upgrading; this release does not introduce a cookie migration.

Source builds now require Go 1.26 or newer. Authentication dependencies enforce
their updated validation rules, so deployments should verify their identity
provider integration before rollout.

## Validation

- Build, vet, module verification, and uncached race tests pass locally.
- Uncached race tests also pass inside the container on Go 1.26.8.
- Container build and a smoke check accepting the legacy CLI flags pass.
- govulncheck on both Go 1.27.1 and container Go 1.26.8 reports no reachable
  vulnerabilities and no vulnerabilities in imported packages. It reports GO-2026-5932 in the unused OpenPGP package of
  golang.org/x/crypto; Beyond does not import that package.
- The inherited external WebSocket echo tests remain skipped. No live SAML
  identity-provider test is included in the existing suite.

