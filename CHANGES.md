# Project Changes

## 2024-11-10: Docker Package Refactoring

### Created `/internal/docker/` Package
Moved Docker registry proxy functionality into a dedicated internal package for better organization and separation of concerns.

**Files:**
- **`docker.go`** - Docker registry proxy implementation
  - `Setup()` - Initialize Docker server proxies
  - `Server` - Docker server with authentication wrapping
  - `ClaimSet` - JWT claim structure for Docker tokens
  - Supports Harbor, GitHub Container Registry, and other Docker registries
  
- **`docker_test.go`** - Docker functionality tests
  - Tests Docker v2 API authentication flow
  - Tests token encoding/decoding with securecookie

**Exported Variables:**
- `DockerBase`, `DockerURLs`, `DockerScheme` - Configuration flags
- `GHPHost` - GitHub Packages hosts configuration
- `Debug`, `LogRoundtrip`, `Handler` - Dependency injection points

**Files Removed:**
- `/docker.go` → `/internal/docker/docker.go`
- `/docker_test.go` → `/internal/docker/docker_test.go`

**Files Updated:**
- **`setup.go`** - Updated to use `docker.Setup()` and configure dependencies
- **`web.go`** - Updated to register Docker handlers and set dependency functions

**Benefits:**
- **Isolation**: Docker proxy logic is now self-contained
- **Testability**: Docker tests run independently in their own package
- **Dependency Injection**: Main package provides handler and logging functions
- **Cleaner API**: Clear separation between Docker proxy and main application logic

---

## 2024-11-08: Authentication and Authorization Package Split

### Split Authentication (authn) from Authorization (authz)
Separated authentication and authorization concerns into distinct internal packages for better separation of concerns and maintainability.

#### Created `/internal/authn/` Package (Authentication)
Handles user identity verification and session management.

**Files:**
- **`session.go`** - Session management with cookie store
- **`token.go`** - Token-based authentication (OAuth2, GitHub tokens)
- **`oidc.go`** - OpenID Connect authentication
- **`saml.go`** - SAML authentication
- **`federate.go`** - Federation support
- **`util.go`** - Utility functions

#### Created `/internal/authz/` Package (Authorization)
Handles access control, permissions, and host rewriting.

**Files:**
- **`acl.go`** - Access Control Lists (fence, sites, allowlist)
  - `RefreshFence()` - Load user fencing configuration
  - `RefreshSites()` - Load allowed sites configuration
  - `RefreshAllowlist()` - Load site allowlist
  - `Allowlisted()` - Check if request is allowlisted
  - `Deny()` - Check if user is denied access
  - `GetSitesURLs()` - Get site URLs for proxy configuration
  - `SetHTTPClient()` - Set HTTP client for ACL operations

- **`hosts.go`** - Host rewriting and mapping
  - `HostsSetup()` - Initialize host mappings from CSV
  - `RefreshHosts()` - Load host mappings from URL
  - `HostAllowed()` - Check if host is allowed
  - `HostRewriteDetailed()` - Get detailed host rewrite info
  - `RewriteHost()` - Get rewritten host (backward compat)
  - `GetHostsMap()`, `SetHostsMap()` - For testing

#### Files Removed
- `/acl.go` → `/internal/authz/acl.go`
- `/masq.go` → `/internal/authz/hosts.go`

#### Files Updated
- **`setup.go`** - Updated to use both `authn` and `authz` packages
- **`handler.go`** - Updated to use `authn` for authentication, `authz` for authorization
- **`proxy.go`** - Updated to use `authz.HostRewriteDetailed()` and `authz.GetSitesURLs()`
- **`web.go`** - Updated to use `authn` package
- **`docker.go`** - Updated to use `authn.GetStore()`
- **Test files** - Updated to use both packages

#### Benefits
- **Clear Separation**: Authentication (who you are) vs Authorization (what you can do)
- **Better Organization**: Related functionality grouped together
- **Easier Testing**: Each concern can be tested independently
- **Maintainability**: Changes to auth logic don't affect authz and vice versa
- **Scalability**: Easier to add new auth methods or authorization rules

---

## 2024-11-08: Authentication Refactoring

### Created `/internal/auth/` Package
Refactored authentication-related code into a dedicated internal package for better organization and maintainability.

#### New Package Structure
- **`/internal/auth/session.go`** - Session management with cookie store
  - `SetupSession()` - Initialize session store
  - `GetSession()` - Retrieve session from request
  - `NewSession()` - Create new session
  - `GetStore()` - Access global session store

- **`/internal/auth/token.go`** - Token-based authentication
  - `TokenAuth()` - Validate and extract user from bearer tokens
  - Supports GitHub API tokens and GraphQL endpoints

- **`/internal/auth/oidc.go`** - OpenID Connect authentication
  - `OIDCSetup()` - Initialize OIDC provider
  - `OIDCVerify()` - Verify OIDC authorization codes
  - `OIDCAuthCodeURL()` - Generate authorization URLs

- **`/internal/auth/saml.go`** - SAML authentication
  - `SAMLSetup()` - Initialize SAML service provider
  - `SAMLFilter()` - Process SAML authentication
  - `SAMLMiddleware()` - Access SAML middleware
  - `SAMLHandleStartAuthFlow()` - Initiate SAML auth flow

- **`/internal/auth/federate.go`** - Federation support
  - `FederateSetup()` - Initialize federation codecs
  - `Federate()` - Handle federation requests
  - `FederateVerify()` - Verify federation tokens

- **`/internal/auth/util.go`** - Utility functions
  - `RandHex32()` - Generate random hex strings

#### Files Removed
- `/token.go` → `/internal/auth/token.go`
- `/oidc.go` → `/internal/auth/oidc.go`
- `/saml.go` → `/internal/auth/saml.go`
- `/federate.go` → `/internal/auth/federate.go`

#### Files Updated
- **`setup.go`** - Updated to use `auth.SetupSession()`, `auth.OIDCSetup()`, `auth.SAMLSetup()`, `auth.FederateSetup()`
- **`handler.go`** - Updated to use `auth.GetSession()`, `auth.TokenAuth()`, `auth.OIDCVerify()`, `auth.RandHex32()`
- **`web.go`** - Updated to use `auth.Federate()`, `auth.FederateVerify()`, `auth.SAMLMiddleware()`
- **`docker.go`** - Updated to use `auth.GetStore()`
- **Test files** - Updated to use auth package exports

#### Flag Variables Moved
All authentication-related flags are now exported from the auth package:
- `auth.CookieName`, `auth.CookieKey`, `auth.CookieAge`, `auth.CookieDom`
- `auth.OIDCIssuer`, `auth.OIDCClientID`, `auth.OIDCClientSecret`
- `auth.SAMLID`, `auth.SAMLIDP`, `auth.SAMLCert`, `auth.SAMLKey`, etc.
- `auth.FederateAccessKey`, `auth.FederateSecretKey`
- `auth.TokenBase`, `auth.TokenGQL`, `auth.TokenGQLQ`

### Benefits
- **Better Organization**: Authentication logic is now isolated in a dedicated package
- **Clearer API**: Exported functions have clear responsibilities
- **Easier Testing**: Auth logic can be tested independently
- **Maintainability**: Related code is grouped together
- **Encapsulation**: Internal implementation details are hidden
