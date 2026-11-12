# Changelog

All notable changes to `pygrindvakt` are documented in this file.

The project is pre-1.0, so minor releases may include behavior changes where
needed to track the upstream `grindvakt` library and correct protocol or
security handling. `pygrindvakt` is a thin PyO3 binding; most entries reflect
adopting a change made in `grindvakt` / `jose-rs` and surfacing it to Python.

## [Unreleased]

### Added

- `ReqwestClient.post_json(url, body, headers=None)`: call a JSON API with a
  POST without adding or configuring another HTTP library. It uses the
  client's timeouts, response-size cap and TLS settings and returns
  `(status, body, content_type)`, where `body` is the raw response bytes
  (decode it with `json.loads`). The request body is serialized compactly,
  dict order is kept and integers are exact; NaN / infinity and over-deep
  nesting raise `ValueError`. `Content-Type: application/json` is set unless the caller
  supplies an `application/json` or `application/*+json` type (kept); any other
  `Content-Type` raises `BadRequestError`, as do client-owned headers (see
  Fixed). Redirects are never followed (including 307 / 308), the response size
  cap applies, and an invalid header raises `BadRequestError`.
- Custom HTTP clients may provide an optional `post_json(url, body, headers)`
  method. Clients without it keep working; a JSON POST through such a client
  raises `ConfigError`. The required protocol (`get` and `post_form`) is
  unchanged.

### Changed

- Bind `grindvakt` 0.12.0. Its only change is a new HTTP client hook that no
  `grindvakt` API calls yet, so behavior is unchanged. No dependency, MSRV or
  security changes.

### Fixed

- `ReqwestClient.get` (with headers), `post_form` and `post_json` now refuse a
  caller-supplied `Content-Length`, `Transfer-Encoding`, `Host`, `Connection`,
  `Expect` or `Content-Encoding` with `BadRequestError` before anything is
  sent. These were forwarded verbatim, so a `Content-Length: 0` silently
  dropped a request body (such as a token request's `client_secret` and code)
  and a `Host` header addressed the request at another virtual host. Code that
  forwards inbound request headers must strip these. `post_form` also now
  reports an invalid header name or value as `BadRequestError` instead of a
  transport error.
- NaN or infinity anywhere in the data handed to JSON conversion (including
  inside sets, frozensets, deques, other sequence- and mapping-like
  containers, dataclass fields, and dict/list/tuple subclasses that override
  their accessors) now raises `ValueError` instead of silently becoming
  `null`. Previously, for example, a NaN inside a set in `jwt.sign` claims or
  a `post_json` body was signed or sent as `null`. Nesting deeper than 127
  levels also raises `ValueError`.
- A dict using the reserved key `$serde_json::private::Number` is now rejected
  with `ValueError` instead of being collapsed into a number (siblings were
  dropped and the NaN check skipped). The one exception: a dict with exactly
  one such entry holding a canonical digit string beyond 128 bits has the shape
  of a genuine big integer, which `pythonize` gives no way to tell apart, so it
  is accepted as that integer. Its length is held to
  `sys.get_int_max_str_digits()` like a real int, so it cannot exceed that limit. The maximum JSON
  nesting depth is now 127 levels; a 128-level body that the converter
  previously accepted is refused.
- A `bytes` value (or `bytes` nested in the data) passed to JSON conversion,
  for example `jwt.sign` claims, `Response.json` or `ReqwestClient.post_json`,
  now raises `TypeError` instead of a bare `Exception`.
- An integer longer than Python's `sys.get_int_max_str_digits()` limit (4300
  digits by default) now raises `ValueError` saying so, instead of an error
  about the reserved big-integer key. Raise the limit to convert such integers.

## [0.4.1] - 2026-11-10

### Changed

- Bind `grindvakt` 0.11.0, a dependency-only release (no API changes): `jose-rs`
  0.11.0, `kryptering` 0.7.1, stable `rsa` 0.10.0 (was `0.10.0-rc.19`) and
  `redis` 1.8.1. Clears the `crypto-bigint` advisories. MSRV stays Rust 1.89.
- `rsa` moved from `=0.10.0-rc.19` to stable 0.10.0: constant-time modular
  exponentiation on `crypto-bigint`, hardened private-key operations, zeroized
  precomputed CRT parameters and PKCS#1 v1.5 implicit rejection.
  RUSTSEC-2023-0071 (Marvin) is fixed by that release, and the fix comes
  through `kryptering` 0.7.1, which dropped its audit exception for it. The
  `RUSTSEC-2023-0071` ignores still present in the `.cargo/audit.toml` of
  `jose-rs` 0.11.0 and `grindvakt` 0.11.0 (and their "no patched release"
  and "rate-limit RSA failures" guidance) are stale and in error, not a
  sign that the advisory is still open in this dependency graph.
  RSA1_5 key transport stays unreachable: `jose-rs` refuses it and the
  `kryptering` `legacy` feature is off.
- `uv.lock`: certifi 2026.10.23, urllib3 2.8.0 and werkzeug 3.1.9, after
  pip-audit flagged the previous versions. These are development and test
  dependencies and are not shipped in the wheel.

### Build and CI

- The wheel build and `just develop` use `--locked`, so a stale `Cargo.lock`
  fails the build instead of being re-resolved.
- The wheel build and the PKCS#11/Redis CI job use a pinned Rust toolchain
  (1.99.1, set in `ci.yml` and `release.yml`). `rustup-init` is pinned to
  1.29.3 and checked against a SHA-256.
- New `audit.yml` workflow: `cargo audit --deny warnings` and `pip-audit` over
  the hashed `uv.lock` export, on lockfile changes, pushes to `main`, weekly
  and on demand. `just audit` runs the cargo side locally.
- `CODEOWNERS` covers the audit policy, pipeline, manifests and lockfiles, and
  Dependabot keeps GitHub Actions references current.
- The test HTTP server no longer prints a `BrokenPipeError` traceback when a
  client times out or aborts.

## [0.4.0] - 2026-10-30

### Added

- RFC 9207 (`iss` on authorization responses) for the in-process `Provider`,
  opt in with `Provider(..., authorization_response_iss=True)` (default
  `False`, behaviour unchanged). Success and error redirects, query or
  fragment, then carry `iss` equal to the issuer, and discovery advertises
  `authorization_response_iss_parameter_supported: true`. The relying party
  side already exists: `rp.parse_authorization_response(...)` then
  `matches_iss(issuer)`.
- `Provider.authorization_error_redirect(request, error)` renders an
  authorization error redirect carrying `iss` when the flag is on (and none
  otherwise; `OAuthError.to_redirect` never adds it). It validates the request
  first and raises the validation `OAuthError` on failure, so a request built
  with `AuthorizationRequest.from_dict` cannot make it redirect to an
  unregistered `redirect_uri`. `state` comes from the error.
- With the flag on, a query-mode response (`authorization_redirect` or
  `authorization_error_redirect`) for a registered `redirect_uri` that already
  has an `iss` query parameter (`%69ss` included) raises
  `OAuthError(server_error)` instead of sending two `iss` values.
- A `Provider` built without the flag but whose metadata advertises
  `authorization_response_iss_parameter_supported: true` now emits the
  existing unimplemented-members `UserWarning`.

### Changed

- `http.Response.redirect`, `Response.with_header`, the `Response.headers`
  setter and the `Response(...)` constructor now validate their input and raise `BadRequestError` (header-injection
  hardening). `redirect` rejects whitespace, control, bidi and invisible
  formatting characters and backslashes in the location (relative targets and
  fragments stay valid; no scheme or host policy); a `location` header set
  through the other three paths gets the same check. Header names must be
  non-empty RFC 9110
  tokens; values may not contain C0 controls (HTAB is allowed), DEL or NUL.
- Added a regression test that `Provider.authorization_redirect` refuses a
  registered `redirect_uri` containing CRLF (core already validates it; no
  behaviour change).
- `rp.asymmetric_algorithms()` takes its names from core's `JWS_ALGORITHMS`
  catalogue (minus `HS*`), intersected with a fixed list of the 11 classical
  asymmetric names, instead of probing that list through the parser. The 11
  names are unchanged; the order now follows core (`ES512`, `EdDSA`,
  `ES256K`). An algorithm core adds later is not listed until the binding
  adds it.
- Python values converted to JSON (claims, metadata, request data) now raise
  `ValueError` on `NaN` and infinity instead of silently becoming `null`
  (previously `jwt.sign(key, {"exp": float("nan")})` signed `exp: null`).
- `Provider.authorization_redirect` and `Provider.authorization_error_redirect`
  now apply the binding's `redirect_uri` rules (no backslash, invisible or bidi
  characters, userinfo) before anything is minted or rendered, and raise
  `OAuthError(invalid_request)` otherwise, even when the client registered the
  URI: core accepted such URIs and they reached the `Location` header.
- `retryable` for upstream HTTP failures uses core's
  `UpstreamHttpError::is_retryable`, and OAuth error codes are parsed with
  core's `OAuthErrorCode::from_str`. Behaviour is unchanged.
- Bound to `grindvakt` 0.10.0 (`jose-rs` 0.10, `kryptering` 0.7). The minimum
  Rust version is now 1.89, as upstream's. Behaviour that follows from core
  0.10: a token is now rejected at `now == exp + leeway` (RFC 7519), so a
  token that expired exactly at the end of the leeway is refused one second
  earlier than before, and a `private_key_jwt` client assertion can no longer
  be replayed while it is still accepted (the `Provider`'s jti replay entry
  now lives until `exp` plus leeway, or `iat` plus the maximum age plus
  leeway).
- JSON <-> Python conversion (`src/convert.rs`) goes through `serde_json`:
  `jose-rs` 0.10 enables `serde_json/arbitrary_precision` and reads `exp`,
  `iat` and `nbf` from a `RawValue`, which `pythonize` alone cannot handle.
  `pythonize` is built with its `arbitrary_precision` feature and `serde_json`
  with `preserve_order`, so numbers stay native `int` / `float` and dicts keep
  insertion order. Shape errors still raise `TypeError`.

## [0.3.0] - 2026-10-29

### Added

- `pygrindvakt.testing`: test-only helpers, plain Python shipped in the wheel and
  not imported by `import pygrindvakt`. `StaticHttpClient(routes, *, default)`
  (URL or `(METHOD, url)` to response or callable; responses are 4-tuples or the
  legacy 3-tuple, other shapes raise `TypeError`; records `.calls`; never
  follows redirects; `get_with_headers`), `ProviderHttpClient(op, issuer, ...)`
  (bridges an RP's discovery / JWKS / token / UserInfo requests to an in-process
  `Provider`; forwards `OAuthError` response headers; discovery and JWKS carry
  `Cache-Control` per keyword `cache_control="max-age=300"`, `None` for none;
  `StaticHttpClient.from_json(..., cache_control=...)` likewise; a route needs
  headers for `JwksCache`/`DiscoveryCache` to avoid the headerless warning),
  `RecordedRequest`,
  `FetchResult` and `mint_id_token(key, *, issuer, client_id, ...)` (refuses
  `extra` overriding protocol claims; `azp`, `auth_time`, `jti`, `acr`, `amr` are
  allowed; `lifetime` must be an int > 0 and `iat` None or an int >= 0, else
  `ValueError`). `ProviderHttpClient` sets `cache-control: no-store` and
  `pragma: no-cache` on token success responses, accepts a form-encoded
  `access_token` on a UserInfo POST (RFC 6750 section 2.2; together with an
  `Authorization` header it is a 400 `invalid_request`) and answers 401 with
  `www-authenticate: Bearer`. DPoP is NOT supported by `ProviderHttpClient`: a
  `DPoP` header or `Authorization: DPoP` scheme on the token or UserInfo
  endpoint raises `NotImplementedError`. `StaticHttpClient` upper-cases the
  method in `(METHOD, url)` route keys. `RecordedRequest.__repr__` redacts
  sensitive header and form values (`RecordedRequest.redacted()` returns a
  redacted copy; attributes stay verbatim, redact before serialising `calls`).
  Request headers and form pairs must be `(str, str)`, else `TypeError`.
  A present `Authorization` header that is not exactly `Bearer <token>` is a 401
  on UserInfo and never falls back to the form `access_token`. See
  `docs/api/testing.rst`.
- `rp.DiscoveryCache(http, issuer, *, default_ttl=3600, min_ttl=60, max_ttl=86400,
  failure_backoff=10, stale_on_error=True, max_stale=86400, fetch_timeout=45.0,
  allow_cross_origin_end_session=False)`: a thread-safe, frozen cache of one
  issuer's discovery document with `metadata()`, `info()`
  (`ProviderInfo.from_metadata`, built once per fetch), `jwks()` (a
  `JwksCache` bound to the advertised `jwks_uri`, the same object across
  refreshes and replaced only when `jwks_uri` or issuer change), `refresh()`
  and the read-only `issuer`, `failure_backoff` and `fetch_timeout`. Lifetime
  from `Cache-Control: max-age` minus `Age` (else `default_ttl`, clamped; the
  same one-time warning for clients that report no headers); single flight
  with waiters bounded by `fetch_timeout` (`InternalError`,
  `code == "discovery_fetch_timeout"`, retryable); no request for
  `failure_backoff` seconds after a failed fetch (`InternalError`,
  `code == "discovery_backoff"`; its `retryable` follows the original error,
  chained as a traceback-free `__cause__`); a waiter that times out is served
  stale metadata under the same policy;
  expired metadata is served after a failed refetch only with
  `stale_on_error=True` and at most `max_stale` seconds past expiry, with a
  one-time `UserWarning` (unlike `JwksCache`, whose keys are never stale; the
  `JwksCache` from `jwks()` keeps that policy). A discovery document whose
  `issuer` differs from the configured one is never cached or served.
  `rp.discover` and `ProviderInfo.from_metadata` are unchanged. See ADR 0008.
- `rp.AuthorizationResponse.verify_jarm(jwks, *, issuer, client_id,
  allowed_algorithms, trust="typed", typ=None, leeway=None)`,
  `AuthorizationResponse.jarm_verified`, `rp.JARM_ASYMMETRIC_ALGORITHMS` and
  `rp.JARM_TYP`: verification of a signed JARM `response` JWT parsed with
  `accept_jarm=True`, replacing "verify it yourself". `jwks` is a key set or a
  `JwksCache`; `allowed_algorithms` is required; `trust` takes `"typed"`
  (default, requires `typ`, default `oauth-authz-resp+jwt`),
  `"dedicated_keys"` or `"untyped_shared_key_compat"`; `HS*` with a
  `JwksCache` raises `ConfigError` (`shared_secret_algorithm`). Raises
  `BadRequestError` (not a stub, JWE, bad inner shape), `ConfigError` (bad
  arguments) or `AuthnError` (signature, `typ`, `kid`, `iss`, `aud`, `exp`;
  a `kid` that names no key in the issuer's JWK Set (after the cache's
  rate-limited refresh, which may have been skipped by the minimum refresh
  interval) is an `AuthnError` with `code == "unknown_kid"` and the original `UnknownKeyError` as `__cause__`; the response is rejected).
  The caller must still call `matches_state` / `matches_iss` on the verified
  result; both are always False on an unverified stub, and an empty JARM
  `response` is rejected. A verified response is replayable until `exp`.
  `parse_authorization_response` now delegates the callback shape rules to
  `grindvakt::callback` (grindvakt 0.9.1, which is now required); the binding
  keeps the input adapter, `error_description_safe` with its own escaper and
  `error_uri` validation. See ADR 0009.
- `rp.parse_authorization_response(params, *, response_mode=None, accept_jarm=False)`
  and the frozen `rp.AuthorizationResponse` (`code`, `state`, `error`,
  `error_description_safe`, `error_uri`, `iss`, `response`, `response_mode`,
  `is_error`, `error_known`, `matches_iss(expected, *, required=True)`,
  `matches_state(expected, *, required=True)`): the
  RP-side counterpart of `request.AuthorizationRequest`, parsing the callback
  fail closed. Accepts an `http.HttpRequestData` (GET query or POST form, with
  a guard against response parameters present in the channel that is not read,
  both for GET and POST), a list of pairs, a `parse_qs`-shaped multi-dict or an
  object with `.lists()` (werkzeug `MultiDict`); a mapping with non-list values
  (a plain `dict[str, str]`) raises `TypeError` naming the key because it
  hides duplicates, and so does an `HttpRequestData` whose read channel
  (`query` for GET, `form` for POST) is non-empty and was built from or
  assigned a mapping (additive tracking; `HttpRequestData` behaviour is
  otherwise unchanged, and its `query` / `form` setters now also accept pairs).
  Raises `BadRequestError` for
  a lone surrogate in a parameter name or value of pairs, multi-dict or
  `.lists()` input (never echoed; only the seven known protocol parameters are
  named; `HttpRequestData` construction still raises `TypeError`),
  repeated parameters, both or neither of `code` / `error`, empty
  `code` / `state` / `error` / `iss`,
  control, bidi / invisible-character or over-2048-character `code` / `state`
  / `iss`, a malformed `error` and (unless `accept_jarm=True`, which exposes
  the raw unverified JWT, and then only as the sole protocol parameter, capped at
  32768 characters) a JARM `response`.
  The raw `error_description` is never exposed, only an escaped, capped
  `error_description_safe`; `error_uri` survives only as a safe, normalised https URL (http only for loopback) with a host;
  unknown error codes are kept (`error_known` is false; "known" is wider than
  what `OAuthError` accepts, so never build `OAuthError(resp.error)`
  unguarded). An empty `expected` makes `matches_iss` / `matches_state` return
  False. `repr()` shows `response=<set>` and escapes quotes. The response proves
  nothing: call `matches_state` (constant-time, fails closed on a missing
  `state`) and `matches_iss` (RFC 9207, fails closed on a missing `iss` unless
  `required=False` because the OP does not advertise
  `authorization_response_iss_parameter_supported`) before exchanging the code. See ADR 0007.
- `rp.validate_issuer`, `rp.validate_redirect_uri_syntax` and
  `rp.validate_service_endpoint(name, endpoint, issuer=None, *, allow_loopback_http=False)`: the core
  syntax validators. `validate_issuer` and `validate_service_endpoint` raise
  `ConfigError` (integrator config / provider metadata);
  `validate_redirect_uri_syntax` raises `BadRequestError` (it can validate
  request input). They check shape only and establish no trust;
  `validate_redirect_uri_syntax` additionally rejects whitespace, control,
  bidi and invisible formatting characters and userinfo (binding-side
  hardening, stricter than core 0.9, also applied to `RpClient`
  `redirect_uris` / `post_logout_redirect_uris` and per-request overrides);
  `validate_redirect_uri_syntax` does not check the scheme (`javascript:` may
  pass). It is the syntax step of `RpClient`'s registration, exact-match and
  transport checks (ADR 0004), not a registration policy: it is not for
  vetting client registrations on an OP, which needs a scheme allow-list and
  exact-match comparison of its own.
  All three also reject backslashes (the URL parser would reinterpret them
  as `/`, so the parsed authority differs from the raw string, for example
  `https://evil.example\@op.example.com`); the same gate covers
  `RpClient` / `JwksCache` / metadata issuer and endpoint URLs and
  `OAuthError.to_redirect`. Compare issuers byte-for-byte (exact string
  match); never suffix/substring checks.
  `validate_service_endpoint` is strict by default (`https` only). The
  loopback-`http` development exception is opt-in via the keyword-only
  `allow_loopback_http=True`, which requires `issuer`: the authenticated,
  locally configured issuer, never taken from the document being validated.
  A loopback-`http` issuer then permits loopback endpoints on any port, and
  accepting a plain `http` endpoint emits a `UserWarning`. Without the opt-in,
  a given `issuer` is still validated (invalid raises `ConfigError`) but never
  enables `http`.
- `rp.MAX_ID_TOKEN_LEEWAY` (300), the cap `verify_id_token` enforces on
  `leeway`, and `rp.asymmetric_algorithms()`, a fixed list of the
  classical asymmetric JWS algorithm names the library parses (no `HS*`,
  `none` or post-quantum names). It is a parser probe, not a recommended
  allowlist, and includes `EdDSA`, which has no OIDC token hash.
- `jwt.oidc_token_hash(alg, value)` and `jwt.supports_oidc_token_hash(alg)`
  for computing `at_hash` / `c_hash`. Computing is not verifying.
  `oidc_token_hash` raises `CryptoError` for an unknown or unparseable `alg`
  (like the other `jwt.*` primitives) and for `EdDSA`;
  `supports_oidc_token_hash` returns `False` for both and never raises.
- `rp.begin()` returns a `rp.BeginResult`, a `collections.namedtuple`
  subclass `(url, state, nonce, code_verifier)` that you can type against.
  It is still a real `tuple` (unpacking, indexing, `==` unchanged). Its
  `repr()` redacts `state`, `nonce` and `code_verifier` and strips the query
  from `url`.
- `rp.TokenSet.refresh_token`, `.expires_in` (non-negative integer up to 10 years,
  315360000 s; a digits-only string is accepted; anything else is `None`,
  which means "absent or not acceptable", NEVER "no expiry": apply your own
  default lifetime and do not treat `None` as unbounded) and `.scope`,
  read from `raw`. `repr()` shows `refresh_token=<set>` / `None`, never the
  value.
- `rp.claims_audiences(claims)`: `aud` as a non-empty list of non-empty
  strings. Fails closed: a missing `aud`, `aud: []`, `aud: ""` or an
  empty-string member raises `BadRequestError`, so `all(a in {CLIENT} for a
  in aud)` cannot pass vacuously; other types, or strings with lone
  surrogates, also raise `BadRequestError`. Convenience only.
- `http.supports_get_with_headers(client)`: whether a client can send headers
  on GET (for `rp.fetch_userinfo(method="GET")`), decided without any request
  and without raising, so an application can fail at startup. Typed as a
  `TypeGuard`, which removes the need for a `cast`.
- `rp.ProviderInfo.metadata`: the discovery document a `ProviderInfo` built by
  `from_metadata` came from, so `ProviderInfo.from_metadata(discover(...))`
  has it (`None` for a hand-built one); `end_session_endpoint` dropped by
  `from_metadata` can be compared with `metadata.end_session_endpoint`, and
  `end_session_url` now says "not advertised", "rejected" or "advertised a
  non-string value" in its `ConfigError`, from the outcome recorded when the
  `ProviderInfo` was built. A non-string advertised `end_session_endpoint`
  (number, object, list ...) now also emits a `UserWarning` and is ignored.
  Every endpoint on `info.metadata` is UNVALIDATED data from the OP: never
  send credentials to them; use the validated properties on the
  `ProviderInfo`.
- `rp.check_rp_compatibility(provider, *, client, pkce, algorithms, scopes,
  acr_values, shared_secret_keys)`: advisory, pure comparison of the RP's intent with the OP's
  advertised metadata (accepts a `ProviderInfo` or the `ProviderMetadata`
  from `discover`); returns mismatch strings, with `not advertised:`
  prefixed informational ones. An absent or empty
  `token_endpoint_auth_methods_supported` assumes the spec default
  `["client_secret_basic"]` (a real mismatch for other auth methods). Mirrors
  ADR 0006: `algorithms` containing `none` is always a mismatch, and `HS*` is a
  mismatch unless `shared_secret_keys=True` (key set derived from the
  client_secret).

### Security

- **Behaviour change (0.3.0):** `jwt.verify_with_jwks` and `jwt.verify_with_jwk`
  now apply the same RFC 7518 section 3.2 minimum-key-length gate as `rp.*`.
  For a token whose header `alg` is `HS256` / `HS384` / `HS512` (and allowed
  by the `Validation`, or any HMAC `alg` when it sets no allow-list), a
  `oct` key the token selects (by `kid`; without one, every key jose-rs
  would try) shorter than 32 / 48 / 64 bytes raises `ConfigError`
  (`code == "weak_shared_secret"`), `k` that is not strict unpadded base64url
  is refused the same way, and a selected `oct` key without an `alg` is
  pinned to the token's `alg`. A weak `oct` key the token does not select does
  not raise. Previously these two functions were ungated: an unpinned
  40-byte `oct` key verified an `HS512` token (the spec needs 64), and a
  16-byte `HS256` key was refused only by jose-rs' key-type heuristic with an
  unrelated error. Callers using short secrets (or relying on the old
  accidental behaviour) with `jwt.verify_with_*` must now use a long enough
  secret; there is no opt-out. A 32-byte unpinned `HS256` key, which the
  heuristic used to reject, now verifies. Asymmetric tokens are unaffected.
- **Behaviour change:** `JwksCache.verify_id_token`, and `rp.verify_id_token` /
  `rp.fetch_userinfo` given a `JwksCache`, now raise `ConfigError`
  (`code == "shared_secret_algorithm"`) when `allowed_algorithms` contains
  `HS256`, `HS384` or `HS512`, before any fetch and with no override. OIDC Core
  section 10.1 derives the MAC key from the `client_secret`, so an OP's
  published JWK Set never carries it. Verify MAC-signed ID tokens with
  `rp.verify_id_token` and a key set you build from the `client_secret`
  (`{"keys": [{"kty": "oct", "k": <base64url(secret)>}]}`); a caller-built key
  set with `HS*` keeps working unchanged. See ADR 0006.
- **Behaviour change:** a symmetric (`oct`) key in a JWK Set fetched from a
  `jwks_uri` is dropped from the result and a `UserWarning` is emitted (once
  per fetch). This covers `rp.fetch_jwks`, `JwksCache` (so `JwksCache.jwks()`
  and the cached set) and the federation helpers `federation.entity_metadata_jwks`
  / `federation.fetch_signed_jwks`. An OP must not publish symmetric keys, so a
  dict from `rp.fetch_jwks` can no longer verify an `HS*` token.
  `federation.entity_metadata_jwks` also filters inline `jwks` metadata. The
  drop is unconditional: a warning filter set to "error" does not stop it.
- **Security:** federation no longer verifies with a symmetric key. An `oct` key
  is now dropped (with a `UserWarning`) from every key set that enters
  federation verification: the `jwks` of `federation.verify` / `verify_typed`,
  the `trust_anchors` map of `federation.resolve_via_trust_anchors`, the
  `subject_fed_jwks` of `federation.entity_metadata_jwks` /
  `federation.fetch_signed_jwks`, and the getters `EntityStatement.jwks()` and
  `ResolvedEntity.subject_jwks`. Before, an entity that published a public
  `oct` key could sign a `jwk-set+jwt` or entity statement with `HS256` and
  have it accepted (injecting an attacker key as the OP's signing key).
  `federation.verify`, `verify_typed` and `verify_self_signed` also refuse a
  token whose header `alg` is `HS256` / `HS384` / `HS512` / `none` with
  `AuthnError` (`code == "symmetric_algorithm"`). See ADR 0006.
  `kty` is matched case-insensitively.
- **Behaviour change:** for a caller-built key set and an `HS*` token,
  `rp.verify_id_token` and `rp.fetch_userinfo` refuse an `oct` key shorter than
  the hash output (32 / 48 / 64 bytes for `HS256` / `HS384` / `HS512`, RFC 7518
  section 3.2) with `ConfigError` (`code == "weak_shared_secret"`; the message
  does not contain the key); only the key the token selects (its `kid`, or
  the only key of a one-key set) is checked, so keep weak keys out of
  verifier sets. Previously `HS384` / `HS512` accepted any `oct`
  key of 33 bytes or more, and a 32-byte `HS256` secret failed with a
  `JoseError` (jose-rs took the unpinned key for an AES key). Only `oct` keys
  usable for HMAC verification with the token's algorithm are checked (`alg`
  absent or equal, `use` absent or `sig`, `key_ops` absent or containing
  `verify`); `k` must be strict unpadded base64url, otherwise the same
  `weak_shared_secret` code is raised with "invalid oct key material". The binding now
  pins the token's `alg` on the selected unpinned `oct` key, so exactly-32-byte `HS256`
  secrets verify. A short `client_secret` with `HS*` is now refused; use a
  secret of at least that length. `none` stays refused when the algorithm
  list is parsed.

### Changed

- Updated to `grindvakt` 0.9.1 (patch release of the 0.9 line; see its changelog).
- The `examples/flask-rp` callback uses `rp.parse_authorization_response`
  (duplicate-safe parsing, constant-time `state` compare, `matches_iss` via the
  explicit `OP_SENDS_ISS` constant, no provider-supplied text on the page) and
  is now covered by end-to-end tests in `tests/test_frameworks.py`.
- **Warning (0.3.0):** `federation.build_entity_configuration` emits a
  `UserWarning` when `public_jwks` contains an `oct` key (OPs and federation
  entities must not publish symmetric keys, OIDC Core section 10.1). The key
  is not dropped. `Provider.jwks_document()` cannot contain one (`HS*` signing
  keys are refused at construction). `rp.fetch_jwks` documents that its `oct`
  drop warning fires once per call (no global dedup), so the returned dict may
  differ from the OP's document. See ADR 0006.

- `OAuthError.to_redirect` now raises `BadRequestError` when the base redirect
  URI contains whitespace/control/bidi/invisible characters or userinfo, is
  unparsable, or has a fragment (header-injection guard); it still does NOT
  check that the URI is registered or that the scheme is acceptable — the
  caller must have exact-matched it against the client's registered URIs first.
- The Flask RP example and the RP/security guides map a failed login to 503
  (`retryable`), 401 (`auth_failure`) or 400 instead of a fixed 502.
- `BadRequestError` and `ConfigError` now also derive from `ValueError` (MRO:
  the class, `GrindvaktError`, `ValueError`, `Exception`). Configuration faults
  in `rp` (`RpClient` auth options, JWS algorithm lists, negative seconds,
  `leeway` range, `JwksCache` constructor, `ProviderInfo` / `RpClient` URLs,
  `fetch_userinfo` options) and `ProviderMetadata` URL/extra checks raise
  `ConfigError` (`status_hint` 500, code `config`), not `BadRequestError`;
  `except ValueError` keeps working, `except GrindvaktError` now catches them.
  Catch `ConfigError` first, log `e.log_summary` and re-raise: it is a
  deployment fault, never a user-visible 4xx or 503. `BadRequestError` (400)
  stays for values that may come from a request (unregistered
  `redirect_uri` / `post_logout_redirect_uri` overrides, reserved `extra`
  parameters). Still plain `ValueError` (follow-up):
  `ProviderMetadata.from_dict`/`from_json` parse failures, rp `extra` and
  `extra_params`, `parse_oauth_code`/`oauth_error_redirect`, and the `client`,
  `tokens`, `dpop`, `provider`, `request` and `http` modules.
- `str(OAuthError)` now escapes control, bidi, invisible-format and tag
  characters in the description and caps it at 512 characters (behaviour
  change). `OAuthError.description` remains raw and untrusted; the wire output
  of `to_response()` / `to_redirect()` is unchanged. `log_summary` now escapes
  the full invisible-character set of grindvakt (tag characters, variation
  selectors and more), not just bidi and zero-width characters.
- `ProviderMetadata(issuer, base)` no longer embeds the nested exception type
  name in its "invalid endpoint" message.

### Added

- `GrindvaktError.auth_failure` (from `Error::is_auth_failure()`; true for
  `AuthnError`), `GrindvaktError.retryable` (upstream status >= 500 or 429, or
  code `transport`, `jwks_fetch_timeout`, `discovery_backoff`) and the
  `GrindvaktError.log_summary` property (safe to log, not to send to clients).
  `retryable` is never derived from an upstream-supplied `code`: an IdP
  answering `error=transport` with HTTP 400/401 stays non-retryable.

## [0.2.0] - 2026-10-13

### Breaking

- `ProviderMetadata` now URL-validates the modelled `authorization_endpoint`,
  `token_endpoint`, `userinfo_endpoint`, `jwks_uri` and `registration_endpoint`
  like extension `*_endpoint` members: the setters, `from_dict` and the
  `ProviderMetadata(issuer, base)` constructor raise `ValueError` for a
  non-https (non-loopback), userinfo-bearing, fragment-bearing or malformed
  URL. Setting `issuer` re-validates them (and the extension URL members)
  against the new issuer and keeps the old one on failure. Hosts are not
  compared with the issuer. The issuer itself is validated too (constructor,
  `from_dict`, setter). An empty-string `userinfo_endpoint` or
  `registration_endpoint` in a document now makes `from_dict` raise; drop the
  key first (`rp.discover` does not apply this check).

### Security

- `rp.verify_id_token` and `JwksCache.verify_id_token` gain keyword-only
  `strict_hashes: bool = False`. When true, it rejects (`AuthnError`) an
  id_token carrying `at_hash` / `c_hash` that cannot be checked (no matching
  `access_token` / `authorization_code`), and requires `at_hash` / `c_hash`
  whenever `access_token` / `authorization_code` is passed (as if
  `require_at_hash` / `require_c_hash` were set), so an id_token not bound to
  the token in hand is refused. With neither value passed and no hash claim,
  nothing is required. `EdDSA` tokens cannot satisfy the requirement. Implicit
  / hybrid flows should pass the values with `require_*_hash` or set
  `strict_hashes=True`; code-flow callers who pass `access_token` but whose OP
  omits `at_hash` must leave it off. The default keeps the lenient behaviour.
- `rp.end_session_url` accepts `post_logout_redirect_uri` only when `client`
  is given and the value exactly equals an entry of the new
  `RpClient(..., post_logout_redirect_uris=[...])` registration; otherwise
  `BadRequestError`. This closes an open redirect
  when the URI came from a request parameter. The `id_token_hint`-only path
  for `post_logout_redirect_uri` is removed (never released).
- The per-call `redirect_uri=` override on `rp.authorization_url`,
  `rp.signed_request_object`, `rp.begin` and `rp.exchange_code` is accepted
  only if it exactly equals the client's `redirect_uri` or an entry of the new
  `RpClient(..., redirect_uris=[...])` registration; otherwise
  `BadRequestError`. This keeps the URL sent to the OP pinned to
  operator-set values even when the override is derived from a request
  parameter. `RpClient(..., allow_unregistered_redirect_uri=True)` is an
  escape hatch (RFC 7591 dynamic registrations) that accepts any valid
  override. `redirect_uris` entries are validated at construction and may not
  be plain `http` to a non-loopback host (`https`, loopback `http` and
  custom/private-use schemes are allowed); the same rule applies to
  unregistered overrides. Breaking relative to earlier unreleased commits,
  where any syntactically valid override was accepted. New read-only
  properties `RpClient.redirect_uris` and
  `RpClient.allow_unregistered_redirect_uri`.

### Changed

- Updated to `grindvakt` 0.9.0 (see its changelog for the full list; notable
  effects for Python users below).
- `JwksCache` now emits one `UserWarning` (per cache, on its first fetch) when
  the `HttpClient` returns a response with no headers at all. Without headers
  the cache cannot see `Cache-Control` / `Age`, so it silently used
  `default_ttl` and a revoked key could stay trusted for that long. The
  built-in client is unaffected, and a custom client avoids the warning and
  gets `Cache-Control` / `Age` handling by returning headers (4-tuple or
  `HttpFetchResponse(headers=...)`; see "Python `HttpClient` adapters can
  report response headers"). Docs now state that `Cache-Control` is honoured
  only when the client reports response headers, and that `no-store` /
  `no-cache` / `max-age=0` are floored to `min_ttl`.

- **Breaking:** `end_session_endpoint` and related OIDC extension members
  (`revocation_endpoint`, `introspection_endpoint`,
  `pushed_authorization_request_endpoint`, `check_session_iframe`,
  `frontchannel_logout_supported`, `backchannel_logout_supported`, ...) were
  previously refused on the OP side because the library implements no logout.
  They are now accepted (RP-Initiated Logout needs `end_session_endpoint`).
  URL-typed members (every `*_endpoint` and `check_session_iframe`) are
  validated on every write path (absolute https URL, or loopback http for a
  loopback issuer; no userinfo, no fragment, no control characters). The host
  is NOT compared with the issuer for `ProviderMetadata` members: an OP may
  publish any host, and an RP consuming metadata from anything other than its
  own TLS discovery must pin the host itself. The RP-side
  `ProviderInfo.end_session_endpoint` IS origin-bound (see below).
  `revocation_endpoint`, `introspection_endpoint`,
  `pushed_authorization_request_endpoint` and `check_session_iframe` are not
  origin-checked anywhere. Validation applies on: `from_dict`, the `extra` setter,
  `set_extra_field` and the typed setters. Inputs that were accepted (for
  example `"javascript:x"` or non-loopback `http://` via `from_dict` /
  `extra` / `set_extra_field`) now raise `ValueError`. The dedicated
  `end_session_endpoint` setter now raises `ValueError` instead of a
  `GrindvaktError` subclass, so all paths agree. `rp.discover` still never
  fails over these members. `service_documentation`, `op_policy_uri` and
  `op_tos_uri` remain type-checked only.
- **Breaking:** `ProviderMetadata.issuer = ...` now re-validates the URL-typed
  members already stored in `extra` against the new issuer and raises
  `ValueError` (naming the member, old issuer kept) if one no longer passes.
- `Provider(...)` emits a `UserWarning` when its metadata advertises
  `end_session_endpoint`, `revocation_endpoint`, `introspection_endpoint`,
  `pushed_authorization_request_endpoint`, `check_session_iframe`, or sets
  `frontchannel_logout_supported` / `backchannel_logout_supported` /
  `require_pushed_authorization_requests` to true: the engine implements none
  of them. Publishing is still allowed; `ProviderMetadata` setters stay silent.

- **Breaking:** known extension members in `ProviderMetadata.extra` are now
  type-checked: a wrong-typed `acr_values_supported`, `backchannel_logout_supported`,
  `revocation_endpoint`, etc. raises `ValueError` from `from_dict`,
  `extra = ...` and `set_extra_field` (previously accepted silently).
- `ProviderMetadata.extra` may now contain `end_session_endpoint`, fixing
  `from_dict(md.to_dict())` raising `ValueError` for discovered documents that
  carry it. `from_dict(md.to_dict()).to_dict() == md.to_dict()` now holds for metadata built
  through the validated paths (not for discovered documents with malformed known
  extension members, which `to_dict()` preserves and `from_dict()` rejects).
- **Breaking:** `rp.fetch_userinfo` now takes `userinfo_endpoint: str | None`
  and raises `ConfigError` for `None`; a signed (`application/jwt`) UserInfo
  response that previously failed generically now raises `AuthnError` with a
  precise code unless verification inputs are supplied. A GET with a Python
  client that supports no headers raises `ConfigError`.

- **Breaking:** exception instances now always have `code` and `upstream_*`
  attributes; code that set or relied on the absence of an attribute named
  `code` on non-`OAuthError` exceptions is affected. `InternalError` raised
  for transport failures now has a `__cause__` where it previously had none.
- **Breaking:** `ProviderMetadata.userinfo_endpoint` is now `str | None`
  (and settable to `None`); providers that do not advertise UserInfo are
  accepted by `rp.discover`, and `ProviderInfo.from_metadata` then yields
  `userinfo_endpoint = None`.
- **Breaking:** `rp.verify_id_token` requires the id_token to carry a `kid`
  when the JWK Set has more than one key (OIDC Core 10.1).
- Failures from the token, UserInfo, JWKS, discovery and federation
  endpoints are reported upstream as `Error::UpstreamHttp`; the binding maps
  token/UserInfo failures to `AuthnError` and the rest to `InternalError`,
  as before. Messages are unchanged except that the token-endpoint message
  no longer embeds the upstream body (`token endpoint returned 400`), and
  the federation resolve failure now reads `resolve endpoint returned N ...`
  under `InternalError`.
- State parameters over 1024 characters or outside printable ASCII are
  rejected, and `OAuthError` wire descriptions are normalized (upstream
  hardening).
- The built-in `ReqwestClient` now records lower-cased response headers on
  the internal fetch response. Python HTTP clients may supply headers too (see
  "Python `HttpClient` adapters can report response headers").
- `py.typed` is now empty (the package is fully typed) instead of `partial`.
- The `http` argument of `rp`, `federation` and `discovery` functions is typed
  as `HttpClientProtocol | ReqwestClient | None` instead of `Any | None`, and
  `HttpClientProtocol` methods are typed as returning a
  `(status, body, content_type)` tuple or an `HttpFetchResponse`.

### Added

- Python `HttpClient` adapters can report response headers: the tuple form
  accepts an optional 4th element `headers: list[tuple[str, str]]` (3-tuples
  keep working) and `HttpFetchResponse` takes an optional `headers` argument
  and exposes a read-only `headers` attribute (names lower-cased, order and
  repeats kept). `JwksCache` uses them for `Cache-Control` / `Age`.

- `rp.JwksCache(http, jwks_uri, issuer, *, default_ttl=3600, min_ttl=60,
  max_ttl=86400, min_refresh_interval=30, fetch_timeout=45.0)`: thread-safe, single-flight JWK Set
  cache honouring `Cache-Control: max-age` minus `Age` (clamped; `no-store` /
  `no-cache` are floored by `min_ttl`), never serving an expired set, with
  `jwks()`, `refresh()` and `verify_id_token(...)`. An unknown `kid` triggers
  one rate-limited refresh, then `UnknownKeyError`. A cache is accepted as
  `jwks=` by `rp.verify_id_token` and `rp.fetch_userinfo`; the `issuer`
  argument must equal the cache's issuer (`BadRequestError` otherwise, before
  any request), so one provider's keys cannot vouch for another's `iss`. A Python
  `HttpClient` gets `Cache-Control` / `Age` handling only if it reports response
  headers (see "Python `HttpClient` adapters can report response headers");
  without headers the cache uses `default_ttl` and warns once.
  `fetch_timeout` (seconds, finite and at least 1e-9, else `ValueError`; default 45, the
  built-in client's 30s timeout plus margin; read-only property of the same name) bounds how long
  a thread waits for another thread's in-flight fetch in `jwks()`, `refresh()`
  and `verify_id_token` (including the unknown-`kid` refresh): the waiter
  raises `InternalError` with `code == "jwks_fetch_timeout"` instead of
  blocking forever. It does not interrupt the fetching thread, so a Python
  `HttpClient` adapter must set its own network timeouts; a stalled adapter
  still stalls its own caller, and its result is cached when it finishes.
- `UnknownKeyError(JoseError)`, `code == "unknown_kid"`, `status_hint` 401.
- `rp.verify_id_token` keyword-only options `leeway` (<= 300), `max_age`
  (checked against `auth_time`, which must be present), `acr_values`,
  `access_token` / `require_at_hash`, `authorization_code` / `require_c_hash`.
  Calls without them behave as before.
- RP-Initiated Logout (OIDC 1.0): `rp.end_session_url(provider, *, id_token_hint,
  client, post_logout_redirect_uri, state, logout_hint, ui_locales, extra)`;
  `ProviderInfo(..., *, end_session_endpoint=None)` and a read-only
  `ProviderInfo.end_session_endpoint` (copied by `from_metadata`; scheme,
  userinfo and fragment validated like other endpoints, and bound to the
  issuer's origin, see below); `ProviderMetadata.end_session_endpoint` (validated
  setter). A `Provider` advertises it when the caller sets it (with a
  `UserWarning`); no logout endpoint is implemented on the OP side.
- `ProviderInfo.end_session_endpoint` must have the same origin as the issuer
  (scheme, case-insensitive/IDNA-normalised host, effective port; `:443` equals
  the default) because `end_session_url` sends `id_token_hint` (the full ID
  token) to that host. The constructor raises `BadRequestError` for a
  cross-origin endpoint; `ProviderInfo.from_metadata` drops it to `None` (so
  login never depends on logout) and `end_session_url` then raises
  `ConfigError` ("missing, unsafe, or on a different origin than the issuer").
  OPs that legitimately log out on another origin opt in with keyword-only
  `allow_cross_origin_end_session=True` on `ProviderInfo(...)` and
  `ProviderInfo.from_metadata(...)`; the scheme/userinfo/fragment checks still
  apply. `ProviderMetadata.end_session_endpoint` stays origin-permissive.
  Migration: `ProviderInfo.from_metadata` now ignores an
  `end_session_endpoint` on a different origin than the issuer (or an unsafe
  one) and emits a `UserWarning` saying so; the strict constructor raises. OPs
  that legitimately log out on another host (for example the AWS Cognito
  hosted UI) need `allow_cross_origin_end_session=True`.
- `ProviderMetadata.raw` (source document snapshot; for `rp.discover` it is the
  fetched body) and `to_dict(*, exclude_defaults=False)`. With
  `exclude_defaults=True`, `to_dict` omits only members equal to their spec
  default, not every `false`, `[]` and `None`, so a source
  `request_uri_parameter_supported: false` (default `true`) stays in the output
  instead of being dropped, which would flip policy. Kept in the output:
  `request_uri_parameter_supported: false`, and `[]` for
  `response_modes_supported`, `grant_types_supported`,
  `token_endpoint_auth_methods_supported`, `claim_types_supported` (non-empty
  spec defaults, so `[]` means "none") and the required
  `response_types_supported`, `subject_types_supported`,
  `id_token_signing_alg_values_supported`. Dropped: `request_uri_parameter_supported:
  true`. Limit: the full `to_dict()` still emits `[]` for absent
  `response_modes_supported`, `grant_types_supported` (and the required lists)
  and `token_endpoint_auth_methods_supported` (the upstream model cannot
  represent absence; a proper fix needs `Option<Vec<_>>` upstream). With
  `exclude_defaults=True` they stay absent when `raw` shows the source lacked
  them and the value is still `[]`; constructor-built metadata (no `raw`)
  keeps the `[]`.
- Typed accessors (`None` when absent) for known extension members stored in
  `extra`: `acr_values_supported`, `claim_types_supported`,
  `revocation_endpoint`, `introspection_endpoint`,
  `pushed_authorization_request_endpoint`, `backchannel_logout_supported`,
  `request_uri_parameter_supported` and others (see the metadata API docs).

- Every pygrindvakt exception has a machine-readable `code` attribute (class
  default, overridden per instance where known, e.g. the upstream OAuth
  `error` such as `invalid_client`, `transport`, `response_too_large`);
  `OAuthError.code` is unchanged. See "Error codes" in the exceptions docs.
- Upstream HTTP failures expose `upstream_status`, `upstream_error`,
  `upstream_error_description` and `upstream_body` (all `None` otherwise).
  The description and body may echo secrets: do not log them or show them to
  end users. `str(exc)` stays generic.
- Outbound transport failures are chained as `__cause__` on the raised
  `InternalError` (`code == "transport"`): the original exception from a
  Python `HttpClient`, or `TimeoutError` / `ConnectionError` / `OSError` from
  `ReqwestClient`. Captured per call, so concurrent calls never mix causes.
- `rp.begin(provider, client, *, extra, redirect_uri, pkce, request_object_key)`
  generates `state`, `nonce` and a PKCE verifier, and returns
  `(url, state, nonce, verifier)`. `pkce=False` is refused for public clients;
  `request_object_key` adds a signed request object.
- Keyword-only `redirect_uri` override on `rp.authorization_url`,
  `rp.signed_request_object` and `rp.exchange_code` (absolute URL, no
  fragment; the same value must be passed to `exchange_code`).

- `rp.fetch_userinfo(..., method="GET")` sends the access token on a GET, and
  signed `application/jwt` UserInfo responses are verified with new keyword
  arguments `jwks`, `client_id`, `allowed_algorithms`, `trust`
  (`"typed"` / `"dedicated_keys"` / `"untyped_shared_key_compat"`), `typ`,
  `max_age` (default 300; `None` disables the age bound and makes replay
  unbounded) and `require_exp`. A signed response without the verification
  inputs raises `AuthnError` with `code == "userinfo_unverifiable"`; JWE is
  rejected (`userinfo_encrypted`). Defaults (POST, JSON) are unchanged.
- `ReqwestClient.get(url, headers=None)` accepts request headers (invalid
  names or values raise `BadRequestError`). Python `HttpClient`s may support
  headers on GET via a keyword-passable `headers` parameter (not positional-only) / `**kwargs` on `get`, or a
  `get_with_headers(url, headers)` method (preferred); the capability is
  decided once, never by catching `TypeError`. Stub-only
  `HttpClientWithHeadersProtocol` / `HttpClientGetWithHeadersProtocol`.
- Tests (two local servers) that credentials and form bodies are never
  forwarded on cross-origin 301/302/303/307/308 redirects.

- CI job running `mypy --strict` over `tests/typecheck_usage.py`.

### Documentation

- `ProviderMetadata.raw` is documented as an unvalidated snapshot for
  display / audit, not for reading policy (extension members read from it
  bypass the type checks; use the typed properties).

- Documented that `from pygrindvakt import http` shadows the standard-library
  `http` package, with `from pygrindvakt import http as gv_http` /
  `import pygrindvakt.http` as alternatives.
- Documented `ReqwestClient` thread safety and fork behaviour (PID-keyed pool,
  per-process runtime, `RedisStore` after fork), and the threading contract of
  Python HTTP clients. Fork is supported only while no other thread is inside
  a pygrindvakt call; a lock held by another thread at fork time is inherited
  locked by the child and can deadlock it.

## [0.1.0] - 2026-09-15

Initial release, binding `grindvakt` 0.8.0 with the `pkcs11` and `redis`
features compiled in.

### Added

- **Breaking:** ``OAuthError.to_redirect`` now requires an explicit response
  mode. Provider construction rejects symmetric ``HS*`` ID-token signing
  keys, and token requests presenting multiple client-authentication methods
  fail with ``invalid_client``.
- **Breaking:** ``rp.fetch_jwks`` and ``rp.fetch_userinfo`` require their
  associated issuer. Loopback HTTP service endpoints are accepted only for
  loopback HTTP issuers
  or federation entities, preventing remote metadata from redirecting token,
  UserInfo, or JWKS traffic to a local plaintext endpoint.
- Updated the protocol engine to `grindvakt` 0.8.0 and added fail-closed OIDC
  validation for endpoints, ID-token algorithms/audiences/subjects, PKCE,
  UserInfo subject binding, response modes, duplicate parameters, and replay
  stores.
- Implemented complete implicit/hybrid authorization responses with OIDC
  `c_hash` / `at_hash`, and stopped issuing ID tokens or UserInfo responses for
  non-OpenID scopes.
- Provider construction now requires an explicit token-use store; DPoP proofs
  can only be obtained through successful validation.
- **Breaking:** Authorization, token, and client-authentication protocol entry
  points require ordered parameter pairs and reject mappings, ensuring duplicate
  names cannot be erased before validation. Trusted session restoration remains
  available through ``AuthorizationRequest.from_dict``.
- ID-token validation now accepts a single-element JSON array in ``aud``
  without requiring ``azp``; a supplied ``azp`` and all multi-audience trust
  checks remain enforced.
- **Breaking:** Authorization requests expose repeated RFC 8707 ``resource``
  parameters via ``AuthorizationRequest.resources`` instead of ``extra``, while
  continuing to reject duplicates of every single-valued protocol parameter.
- One Python submodule per grindvakt module: `http`, `keys`, `client`,
  `metadata`, `request`, `tokens`, `provider`, `dpop`, `rp`, `federation`,
  `discovery`, `jwt`, `pkce`, `mac`, `util`.
- Synchronous Python API over grindvakt's async Rust, driven by a process-wide
  tokio runtime with the GIL released; PID-keyed so it survives `fork`
  (ADR 0001).
- Python protocol adapters for `HttpClient`, `ClientStore`, `TokenUseStore` and
  `ReplayStore`, all failing closed (ADR 0002).
- Built-in `http.ReqwestClient` (rustls, timeouts, no redirects, streamed size
  cap) and `provider.RedisStore` (fork-guarded).
- `dpop.InMemoryReplayStore`, which grindvakt itself does not ship.
- `OAuthError` exception carrying `code` / `description` / `state` with
  `to_response()` / `to_redirect()`; typed `GrindvaktError` and `DpopError`
  subclasses.
- Fail-closed hardening beyond upstream (ADR 0003): nonce required in
  `rp.verify_id_token`, duplicate `client_id` rejected, unknown `Client`
  fields rejected, reserved id_token claims in `extra_claims` rejected,
  `NoReplayStore` without `require_nonce` warns.
- Type stubs for every submodule; Sphinx documentation; Flask, Django and
  FastAPI OpenID Provider examples plus a Flask Relying Party.
