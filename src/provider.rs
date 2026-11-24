//! Bindings for `grindvakt::provider` - the OpenID Provider engine.
//!
//! A `Provider` is constructed once at startup and shared across requests. Its
//! endpoint methods take already-extracted ordered pairs and header
//! strings) and return `Response` objects or raise `OAuthError`, so any web
//! framework can drive it: see `examples/` for Flask, Django and FastAPI.
//!
//! One-time use of authorization codes / refresh tokens / `private_key_jwt`
//! `jti`s is enforced through a `TokenUseStore`: `InMemoryTokenUseStore`
//! (single process), `RedisStore` (shared), or any Python object with
//! `consume(token_hash: str, ttl_secs: int) -> bool`.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use grindvakt::provider as gp;
use grindvakt::provider::TokenUseStore;

use crate::client::{extract_client_store, Client};
use crate::convert::{
    from_py, log_unraisable, new_submodule, protocol_parameter_pairs, require_methods, to_py,
};
use crate::dpop::DpopProof;
use crate::errors::{build_oauth_error, err, internal_err, oauth_err};
use crate::http::Response;
use crate::keys::SigningKey;
use crate::metadata::ProviderMetadata;
use crate::request::AuthorizationRequest;
use crate::tokens::TokenCodec;

const RESERVED_ID_TOKEN_CLAIMS: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "nonce",
    "auth_time",
    "acr",
    "azp",
    "at_hash",
    "c_hash",
];

/// Per-destination claim release decisions for
/// `Provider.authorization_redirect_with_authorized_claims`.
#[pyclass(module = "pygrindvakt.provider", name = "AuthorizedClaims", frozen)]
pub struct AuthorizedClaims {
    id_token: BTreeMap<String, serde_json::Value>,
    userinfo: BTreeMap<String, serde_json::Value>,
}

fn claim_map(obj: &Bound<'_, PyAny>, what: &str) -> PyResult<BTreeMap<String, serde_json::Value>> {
    if obj.is_none() {
        return Err(PyTypeError::new_err(format!(
            "{what} must be a dict, not None"
        )));
    }
    let map: BTreeMap<String, serde_json::Value> = from_py(obj)?;
    let reserved: Vec<&String> = map
        .keys()
        .filter(|k| RESERVED_ID_TOKEN_CLAIMS.contains(&k.as_str()))
        .collect();
    if !reserved.is_empty() {
        return Err(PyValueError::new_err(format!(
            "{what} must not contain reserved id_token claim(s): {reserved:?}"
        )));
    }
    Ok(map)
}

#[pymethods]
impl AuthorizedClaims {
    #[new]
    #[pyo3(signature = (*, id_token, userinfo))]
    fn new(id_token: &Bound<'_, PyAny>, userinfo: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self {
            id_token: claim_map(id_token, "id_token")?,
            userinfo: claim_map(userinfo, "userinfo")?,
        })
    }
    #[getter]
    fn id_token<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.id_token)
    }
    #[getter]
    fn userinfo<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.userinfo)
    }
    fn __repr__(&self) -> String {
        let id: Vec<&String> = self.id_token.keys().collect();
        let ui: Vec<&String> = self.userinfo.keys().collect();
        format!("AuthorizedClaims(id_token={id:?}, userinfo={ui:?})")
    }
}

// ---------------------------------------------------------------------------
// TokenLifetimes / TokenResponse
// ---------------------------------------------------------------------------

/// Lifetimes (seconds) of issued artefacts.
#[pyclass(
    module = "pygrindvakt.provider",
    name = "TokenLifetimes",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct TokenLifetimes {
    pub inner: gp::TokenLifetimes,
}

#[pymethods]
impl TokenLifetimes {
    #[new]
    #[pyo3(signature = (*, code_ttl = 600, access_token_ttl = 3600, id_token_ttl = 3600,
                        refresh_token_ttl = 2_592_000))]
    fn new(
        code_ttl: u64,
        access_token_ttl: u64,
        id_token_ttl: u64,
        refresh_token_ttl: u64,
    ) -> Self {
        Self {
            inner: gp::TokenLifetimes {
                code_ttl,
                access_token_ttl,
                id_token_ttl,
                refresh_token_ttl,
            },
        }
    }
    #[getter]
    fn code_ttl(&self) -> u64 {
        self.inner.code_ttl
    }
    #[getter]
    fn access_token_ttl(&self) -> u64 {
        self.inner.access_token_ttl
    }
    #[getter]
    fn id_token_ttl(&self) -> u64 {
        self.inner.id_token_ttl
    }
    #[getter]
    fn refresh_token_ttl(&self) -> u64 {
        self.inner.refresh_token_ttl
    }
    fn __repr__(&self) -> String {
        format!(
            "TokenLifetimes(code_ttl={}, access_token_ttl={}, id_token_ttl={}, refresh_token_ttl={})",
            self.inner.code_ttl,
            self.inner.access_token_ttl,
            self.inner.id_token_ttl,
            self.inner.refresh_token_ttl
        )
    }
}

/// A successful token-endpoint response. `to_dict()` is exactly the JSON body
/// to send (with `cache-control: no-store`).
#[pyclass(module = "pygrindvakt.provider", name = "TokenResponse", frozen)]
pub struct TokenResponse {
    pub inner: gp::TokenResponse,
}

#[pymethods]
impl TokenResponse {
    #[getter]
    fn access_token(&self) -> &str {
        &self.inner.access_token
    }
    #[getter]
    fn token_type(&self) -> &str {
        &self.inner.token_type
    }
    #[getter]
    fn expires_in(&self) -> u64 {
        self.inner.expires_in
    }
    #[getter]
    fn id_token(&self) -> Option<&str> {
        self.inner.id_token.as_deref()
    }
    #[getter]
    fn scope(&self) -> Option<&str> {
        self.inner.scope.as_deref()
    }
    #[getter]
    fn refresh_token(&self) -> Option<&str> {
        self.inner.refresh_token.as_deref()
    }
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner)
    }
    /// The complete HTTP response: 200, JSON body, `cache-control: no-store`.
    fn to_response(&self) -> PyResult<Response> {
        grindvakt::http::Response::json(&self.inner)
            .map(|r| Response::wrap(r.with_header("cache-control", "no-store")))
            .map_err(crate::errors::err)
    }
    fn __repr__(&self) -> String {
        format!(
            "TokenResponse(token_type={:?}, expires_in={}, id_token={}, refresh_token={})",
            self.inner.token_type,
            self.inner.expires_in,
            self.inner.id_token.is_some(),
            self.inner.refresh_token.is_some()
        )
    }
}

// ---------------------------------------------------------------------------
// Token-use stores
// ---------------------------------------------------------------------------

/// Process-local one-time-use store for codes, refresh tokens and assertion
/// `jti`s. Fine for a single process; use `RedisStore` or a Python-backed
/// store across replicas.
#[pyclass(
    module = "pygrindvakt.provider",
    name = "InMemoryTokenUseStore",
    frozen
)]
pub struct InMemoryTokenUseStore {
    pub inner: Arc<gp::InMemoryTokenUseStore>,
}

#[pymethods]
impl InMemoryTokenUseStore {
    #[new]
    fn new() -> Self {
        Self {
            inner: Arc::new(gp::InMemoryTokenUseStore::new()),
        }
    }
    /// Mark `token_hash` used; True iff it was not already used.
    fn consume(&self, py: Python<'_>, token_hash: String, ttl_secs: u64) -> PyResult<bool> {
        let s = self.inner.clone();
        crate::runtime::block_on(py, async move { s.consume(&token_hash, ttl_secs).await })?
            .map_err(internal_err)
    }
    fn __repr__(&self) -> &'static str {
        "InMemoryTokenUseStore()"
    }
}

/// Fork guard around grindvakt's `RedisStore`: its connection-manager tasks
/// live on the runtime of the process that created it, so use from a forked
/// child would hang. Fail closed with a clear message instead.
pub struct ForkGuardedRedisStore {
    inner: gp::RedisStore,
    pid: u32,
}

#[async_trait]
impl TokenUseStore for ForkGuardedRedisStore {
    async fn consume(&self, h: &str, ttl: u64) -> Result<bool, String> {
        if std::process::id() != self.pid {
            return Err(
                "RedisStore was created before fork; construct it in the worker process".into(),
            );
        }
        self.inner.consume(h, ttl).await
    }
}

/// Redis-backed one-time-use store (`SET key 1 EX ttl NX`) for multi-process
/// deployments. Construct it *after* fork (e.g. in a gunicorn `post_fork`
/// hook or lazily in the worker).
#[pyclass(module = "pygrindvakt.provider", name = "RedisStore", frozen)]
pub struct RedisStore {
    pub inner: Arc<ForkGuardedRedisStore>,
}

#[pymethods]
impl RedisStore {
    #[new]
    #[pyo3(signature = (redis_url, key_prefix = None))]
    fn new(redis_url: &str, key_prefix: Option<String>) -> PyResult<Self> {
        // ConnectionManager spawns a background task at construction, so the
        // runtime context must be entered on this thread.
        let _guard = crate::runtime::enter();
        let mut store = gp::RedisStore::new(redis_url)
            .map_err(|e| crate::errors::config_err(format!("redis: {e}")))?;
        if let Some(p) = key_prefix {
            store = store.with_key_prefix(p);
        }
        Ok(Self {
            inner: Arc::new(ForkGuardedRedisStore {
                inner: store,
                pid: std::process::id(),
            }),
        })
    }
    fn consume(&self, py: Python<'_>, token_hash: String, ttl_secs: u64) -> PyResult<bool> {
        let s = self.inner.clone();
        crate::runtime::block_on(py, async move { s.consume(&token_hash, ttl_secs).await })?
            .map_err(internal_err)
    }
    #[classattr]
    const DEFAULT_KEY_PREFIX: &'static str = gp::RedisStore::DEFAULT_KEY_PREFIX;
    fn __repr__(&self) -> &'static str {
        "RedisStore(<redis>)"
    }
}

/// Adapter over a Python object implementing `consume(token_hash, ttl_secs) -> bool`.
/// An exception is reported as a store failure, which grindvakt renders as
/// `server_error`.
pub struct PyTokenUseStore {
    obj: Py<PyAny>,
}

#[async_trait]
impl TokenUseStore for PyTokenUseStore {
    async fn consume(&self, token_hash: &str, ttl_secs: u64) -> Result<bool, String> {
        Python::attach(|py| {
            let obj = self.obj.bind(py);
            match obj
                .call_method1("consume", (token_hash, ttl_secs))
                .and_then(|r| r.extract::<bool>())
            {
                Ok(b) => Ok(b),
                Err(e) => {
                    let msg = format!("python TokenUseStore.consume raised: {e}");
                    log_unraisable(py, e, obj, "TokenUseStore.consume");
                    Err(msg)
                }
            }
        })
    }
}

pub fn extract_token_use_store(obj: &Bound<'_, PyAny>) -> PyResult<Arc<dyn TokenUseStore>> {
    if let Ok(s) = obj.cast::<InMemoryTokenUseStore>() {
        return Ok(s.get().inner.clone());
    }
    if let Ok(s) = obj.cast::<RedisStore>() {
        return Ok(s.get().inner.clone());
    }
    require_methods(obj, &["consume"], "TokenUseStore")?;
    Ok(Arc::new(PyTokenUseStore {
        obj: obj.clone().unbind(),
    }))
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/// The OpenID Provider engine. Build once, share across requests.
///
/// `clients` is an `InMemoryClientStore` or any object implementing the
/// `ClientStore` protocol. `token_use_store` is mandatory so multi-process
/// deployments cannot silently select process-local replay protection.
#[pyclass(module = "pygrindvakt.provider", name = "Provider", frozen)]
pub struct Provider {
    pub inner: Arc<gp::Provider>,
    clients_obj: Py<PyAny>,
    token_use_store_obj: Py<PyAny>,
}

/// Warn (once, listing all names) when the metadata advertises members for
/// behaviour this engine does not implement. Publishing is still allowed.
/// `emits_iss` is the `authorization_response_iss` flag: the RFC 9207 member
/// is only a claim about the front end when the engine is not emitting `iss`.
fn warn_unimplemented_members(metadata: &ProviderMetadata, emits_iss: bool) -> PyResult<()> {
    const ALWAYS: &[&str] = &[
        "end_session_endpoint",
        "revocation_endpoint",
        "introspection_endpoint",
        "pushed_authorization_request_endpoint",
        "check_session_iframe",
    ];
    const WHEN_TRUE: &[&str] = &[
        "frontchannel_logout_supported",
        "backchannel_logout_supported",
        "require_pushed_authorization_requests",
    ];
    let extra = &metadata.inner.extra;
    let mut names: Vec<&str> = ALWAYS
        .iter()
        .copied()
        .filter(|k| extra.contains_key(*k))
        .collect();
    names.extend(
        WHEN_TRUE
            .iter()
            .copied()
            .filter(|k| extra.get(*k).and_then(serde_json::Value::as_bool) == Some(true)),
    );
    const ISS_MEMBER: &str = "authorization_response_iss_parameter_supported";
    if !emits_iss && extra.get(ISS_MEMBER).and_then(serde_json::Value::as_bool) == Some(true) {
        names.push(ISS_MEMBER);
    }
    if names.is_empty() {
        return Ok(());
    }
    Python::attach(|py| {
        let msg = std::ffi::CString::new(format!(
            "Provider does not implement {}; advertising them is a claim you are making about your own front end.",
            names.join(", ")
        ))
        .expect("no NUL in warning");
        PyErr::warn(
            py,
            &py.get_type::<pyo3::exceptions::PyUserWarning>(),
            &msg,
            1,
        )
    })
}

/// The binding's `redirect_uri` rules (the ones `OAuthError.to_redirect` and
/// `RpClient` apply) before a registered URI is echoed into a `Location`
/// header: core accepts a backslash, invisible formatting characters and
/// userinfo that these reject. Fixed message; the URI is never echoed.
fn check_redirect_target(py: Python<'_>, request: &AuthorizationRequest) -> PyResult<()> {
    crate::rp::check_redirect_uri(&request.inner.redirect_uri).map_err(|_| match build_oauth_error(
        "invalid_request",
        Some("redirect_uri is not safe to redirect to".into()),
        None,
    ) {
        Ok(e) => oauth_err(py, &e),
        Err(e) => e,
    })
}

#[pymethods]
impl Provider {
    #[new]
    #[pyo3(signature = (metadata, signing_key, clients, codec, lifetimes = None,
                        token_use_store = None, client_assertion_max_age = None,
                        authorization_response_iss = false))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        metadata: &ProviderMetadata,
        signing_key: &SigningKey,
        clients: &Bound<'_, PyAny>,
        codec: &TokenCodec,
        lifetimes: Option<&TokenLifetimes>,
        token_use_store: Option<&Bound<'_, PyAny>>,
        client_assertion_max_age: Option<u64>,
        authorization_response_iss: bool,
    ) -> PyResult<Self> {
        let store = extract_client_store(clients)?;
        let (token_use_store, token_use_store_obj) = match token_use_store {
            Some(t) if !t.is_none() => (extract_token_use_store(t)?, t.clone().unbind()),
            _ => return Err(PyValueError::new_err(
                "token_use_store is required; pass InMemoryTokenUseStore() explicitly only for a single-process deployment",
            )),
        };
        let mut p = gp::Provider::new(
            metadata.inner.clone(),
            signing_key.inner.clone(),
            store,
            codec.inner.clone(),
            lifetimes.map(|l| l.inner.clone()).unwrap_or_default(),
            token_use_store,
        )
        .map_err(err)?;
        if let Some(secs) = client_assertion_max_age {
            p = p.with_client_assertion_max_age(secs);
        }
        if authorization_response_iss {
            p = p.with_authorization_response_iss();
        }
        // Last, after every fallible step, so a failing constructor never warns.
        warn_unimplemented_members(metadata, authorization_response_iss)?;
        Ok(Self {
            inner: Arc::new(p),
            clients_obj: clients.clone().unbind(),
            token_use_store_obj,
        })
    }

    /// The client store passed at construction.
    #[getter]
    fn clients(&self, py: Python<'_>) -> Py<PyAny> {
        self.clients_obj.clone_ref(py)
    }
    /// The token-use store in effect.
    #[getter]
    fn token_use_store(&self, py: Python<'_>) -> Py<PyAny> {
        self.token_use_store_obj.clone_ref(py)
    }
    #[getter]
    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata::wrap(self.inner.metadata.clone())
    }
    #[getter]
    fn signing_key(&self) -> SigningKey {
        SigningKey::wrap(self.inner.signing_key.clone())
    }
    #[getter]
    fn lifetimes(&self) -> TokenLifetimes {
        TokenLifetimes {
            inner: self.inner.lifetimes.clone(),
        }
    }
    #[getter]
    fn issuer(&self) -> &str {
        &self.inner.metadata.issuer
    }

    /// The `/.well-known/openid-configuration` document as a dict.
    fn discovery_document<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner.discovery_document())
    }
    /// The JWKS document (`{"keys": [...]}`) as a dict.
    fn jwks_document<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner.jwks_document())
    }

    /// Validate an authorization request against the registered client and
    /// return that `Client`.
    ///
    /// On failure the `redirect_uri` is NOT trusted: render the raised
    /// `OAuthError` with `.to_response()`, never `.to_redirect()`.
    fn validate_authorization_request(
        &self,
        py: Python<'_>,
        request: &AuthorizationRequest,
    ) -> PyResult<Client> {
        let p = self.inner.clone();
        let req = request.inner.clone();
        let r =
            crate::runtime::block_on(
                py,
                async move { p.validate_authorization_request(&req).await },
            )?;
        r.map(Client::wrap).map_err(|e| oauth_err(py, &e))
    }

    /// After the user authenticated: mint the code / tokens for `sub` and
    /// return the redirect `Response` back to the client.
    ///
    /// `external_claims` maps claim name -> list of string values (multi-valued
    /// claims become JSON arrays; single values are coerced for standard
    /// claims such as `email_verified`). `extra_claims` are typed id_token
    /// claims; protocol-owned claims such as `sub`, `nonce`, `azp`, `at_hash`,
    /// and `c_hash` raise `ValueError`. The request is validated again at this
    /// minting boundary, and an empty subject is rejected.
    ///
    /// On `OAuthError`, use fragment mode when `request.use_fragment()` is
    /// true; otherwise use query mode. This preserves the successful response's
    /// delivery mode without exposing a token-bearing flow in the query. When
    /// the Provider was built with `authorization_response_iss=True`, render
    /// the error with `Provider.authorization_error_redirect` instead so it
    /// carries `iss` too; `OAuthError.to_redirect` never adds it. With that
    /// flag on, a query-mode response whose registered `redirect_uri` already
    /// has an `iss` query parameter raises `OAuthError(server_error)`.
    ///
    /// For separate ID token and UserInfo release, use
    /// `authorization_redirect_with_authorized_claims`.
    #[pyo3(signature = (request, sub, external_claims = None, acr = None, extra_claims = None))]
    fn authorization_redirect(
        &self,
        py: Python<'_>,
        request: &AuthorizationRequest,
        sub: &str,
        external_claims: Option<BTreeMap<String, Vec<String>>>,
        acr: Option<String>,
        extra_claims: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Response> {
        check_redirect_target(py, request)?;
        let extra: BTreeMap<String, serde_json::Value> = match extra_claims {
            Some(v) if !v.is_none() => from_py(v)?,
            _ => BTreeMap::new(),
        };
        let reserved: Vec<&String> = extra
            .keys()
            .filter(|k| RESERVED_ID_TOKEN_CLAIMS.contains(&k.as_str()))
            .collect();
        if !reserved.is_empty() {
            return Err(PyValueError::new_err(format!(
                "extra_claims must not contain reserved id_token claim(s): {reserved:?}"
            )));
        }
        let p = self.inner.clone();
        let request = request.inner.clone();
        let external_claims = external_claims.unwrap_or_default();
        let result = crate::runtime::block_on(py, async move {
            p.authorization_redirect_with_claims(&request, sub, &external_claims, acr, &extra)
                .await
        })?;
        result.map(Response::wrap).map_err(|e| oauth_err(py, &e))
    }

    /// Like `authorization_redirect`, but with separate ID token and UserInfo
    /// release decisions in `claims` (an `AuthorizedClaims`). `sub` must be a
    /// public subject: pairwise clients raise `OAuthError(unauthorized_client)`.
    ///
    /// No scope filter is applied: the caller decides what each destination
    /// receives. The registration fingerprint is sealed into the code, so
    /// redemption and refresh detect a changed registration.
    #[pyo3(signature = (request, sub, claims, *, acr = None, auth_time = None))]
    fn authorization_redirect_with_authorized_claims(
        &self,
        py: Python<'_>,
        request: &AuthorizationRequest,
        sub: &str,
        claims: &AuthorizedClaims,
        acr: Option<String>,
        auth_time: Option<u64>,
    ) -> PyResult<Response> {
        check_redirect_target(py, request)?;
        let p = self.inner.clone();
        let req = request.inner.clone();
        let sub = sub.to_owned();
        let authorized = gp::AuthorizedClaims {
            id_token: claims.id_token.clone(),
            userinfo: claims.userinfo.clone(),
        };
        let result = crate::runtime::block_on(py, async move {
            let state = req.state.clone();
            p.authorization_redirect_with_authorized_claims(
                &req,
                |client| {
                    if client.subject_type != "public" {
                        return Err(grindvakt::OAuthError::new(
                            grindvakt::OAuthErrorCode::UnauthorizedClient,
                            "pairwise subjects require an issuance-time subject resolver",
                        )
                        .with_state(state));
                    }
                    Ok(sub)
                },
                authorized,
                acr,
                auth_time,
            )
            .await
        })?;
        result.map(Response::wrap).map_err(|e| oauth_err(py, &e))
    }

    /// Render an authorization error redirect for `request`, in its response
    /// mode, with `state` taken from `error` (as `OAuthError.to_redirect`
    /// does; pass `request.state` yourself). With
    /// `authorization_response_iss=True` the redirect carries `iss` (RFC 9207);
    /// without it no `iss` is added.
    ///
    /// The request is validated first (as in `validate_authorization_request`),
    /// so a request rebuilt with `AuthorizationRequest.from_dict` can never
    /// make this an open redirector: on failure the validation `OAuthError` is
    /// raised and you render it with `.to_response()`. With the flag on it
    /// also raises `OAuthError(server_error)` in query mode when the
    /// registered `redirect_uri` already has an `iss` query parameter.
    fn authorization_error_redirect(
        &self,
        py: Python<'_>,
        request: &AuthorizationRequest,
        error: &Bound<'_, PyAny>,
    ) -> PyResult<Response> {
        check_redirect_target(py, request)?;
        let code: String = error.getattr("code")?.extract()?;
        let description: Option<String> = error.getattr("description")?.extract()?;
        let state: Option<String> = error.getattr("state")?.extract()?;
        let rs_error = build_oauth_error(&code, description, state)?;
        let p = self.inner.clone();
        let request = request.inner.clone();
        let result = crate::runtime::block_on(py, async move {
            // Fail closed: never build a redirect for an unvalidated redirect_uri.
            p.validate_authorization_request(&request).await?;
            p.authorization_error_redirect(&request, &rs_error)
        })?;
        result.map(Response::wrap).map_err(|e| oauth_err(py, &e))
    }

    /// Handle a token-endpoint request.
    ///
    /// `form` is the ordered parsed form body. Mappings are rejected because
    /// they may already have erased duplicates. `auth_header` is the raw `Authorization`
    /// header, `token_url` the absolute token endpoint URL *from
    /// configuration* (it is the `private_key_jwt` audience and the DPoP
    /// `htu`), and `dpop` an already-validated `DpopProof` if the request
    /// carried one. Raises `OAuthError`; render it with `.to_response()`.
    #[pyo3(signature = (form, token_url, auth_header = None, dpop = None))]
    /// Handle a token request from ordered form pairs so duplicate OAuth
    /// parameters are rejected before processing.
    fn handle_token_request(
        &self,
        py: Python<'_>,
        form: &Bound<'_, PyAny>,
        token_url: String,
        auth_header: Option<String>,
        dpop: Option<DpopProof>,
    ) -> PyResult<TokenResponse> {
        let form = protocol_parameter_pairs(form, "token form")?;
        let p = self.inner.clone();
        let dpop = dpop.map(|d| d.inner);
        let r = crate::runtime::block_on(py, async move {
            p.handle_token_request(&form, auth_header.as_deref(), &token_url, dpop.as_ref())
                .await
        })?;
        r.map(|inner| TokenResponse { inner })
            .map_err(|e| oauth_err(py, &e))
    }

    /// Handle a userinfo request: require an `openid`-scoped access token,
    /// validate it (and, for a DPoP-bound token, its `presented_jkt`), and
    /// return the subject and scope-filtered claims.
    #[pyo3(signature = (access_token, presented_jkt = None))]
    fn userinfo<'py>(
        &self,
        py: Python<'py>,
        access_token: String,
        presented_jkt: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let p = self.inner.clone();
        let r = crate::runtime::block_on(py, async move {
            p.userinfo(&access_token, presented_jkt.as_deref()).await
        })?;
        let v = r.map_err(|e| oauth_err(py, &e))?;
        to_py(py, &v)
    }

    /// Handle a UserInfo request and return the response as a signed JWT.
    ///
    /// Same checks as `userinfo`. The compact JWS has `typ` `userinfo+jwt`,
    /// `iss`, `aud` = client_id and `exp` = min(access token exp, now + 300).
    /// A client registered with `userinfo_encrypted_response_alg` receives a
    /// compact JWE instead. Serve it with `content-type: application/jwt`.
    #[pyo3(signature = (access_token, presented_jkt = None))]
    fn signed_userinfo(
        &self,
        py: Python<'_>,
        access_token: String,
        presented_jkt: Option<String>,
    ) -> PyResult<String> {
        let p = self.inner.clone();
        let r = crate::runtime::block_on(py, async move {
            p.signed_userinfo(&access_token, presented_jkt.as_deref())
                .await
        })?;
        r.map_err(|e| oauth_err(py, &e))
    }

    /// Record a verified request object `jti` for one-time use by `client_id`.
    ///
    /// Call after verifying the request object's signature and binding it to
    /// the client. `expiry` is the acceptance deadline in Unix seconds. Returns
    /// `None`; raises `OAuthError`: `invalid_request` for an empty or
    /// over-512-byte `jti` or an `expiry` not in the future, `invalid_grant`
    /// on reuse, `server_error` on store failure. Replicas need a shared
    /// `token_use_store`.
    fn consume_request_id(
        &self,
        py: Python<'_>,
        client_id: String,
        jti: String,
        expiry: u64,
    ) -> PyResult<()> {
        let p = self.inner.clone();
        let r = crate::runtime::block_on(py, async move {
            p.consume_request_id(&client_id, &jti, expiry).await
        })?;
        r.map_err(|e| oauth_err(py, &e))
    }

    /// Authenticate a client from a token-endpoint style request (form +
    /// `Authorization` header) and return the `Client`. Mappings are rejected;
    /// ordered form pairs preserve duplicate names for rejection.
    #[pyo3(signature = (form, token_url, auth_header = None))]
    fn authenticate_client(
        &self,
        py: Python<'_>,
        form: &Bound<'_, PyAny>,
        token_url: String,
        auth_header: Option<String>,
    ) -> PyResult<Client> {
        let form = protocol_parameter_pairs(form, "token form")?;
        let p = self.inner.clone();
        let r = crate::runtime::block_on(py, async move {
            p.authenticate_client(&form, auth_header.as_deref(), &token_url)
                .await
        })?;
        r.map(Client::wrap).map_err(|e| oauth_err(py, &e))
    }

    fn __repr__(&self) -> String {
        format!("Provider(issuer={:?})", self.inner.metadata.issuer)
    }
}

/// Flatten `{claim: [values]}` into id_token / userinfo claim values the way
/// the provider does (single values coerced for standard claims).
#[pyfunction]
fn flatten_claims<'py>(
    py: Python<'py>,
    external: BTreeMap<String, Vec<String>>,
) -> PyResult<Bound<'py, PyAny>> {
    to_py(py, &gp::flatten_claims(&external))
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "provider")?;
    m.add_class::<TokenLifetimes>()?;
    m.add_class::<AuthorizedClaims>()?;
    m.add_class::<TokenResponse>()?;
    m.add_class::<InMemoryTokenUseStore>()?;
    m.add_class::<RedisStore>()?;
    m.add_class::<Provider>()?;
    m.add_function(wrap_pyfunction!(flatten_claims, &m)?)?;
    m.add("CLIENT_ASSERTION_TYPE", gp::CLIENT_ASSERTION_TYPE)?;
    m.add(
        "DEFAULT_CLIENT_ASSERTION_MAX_AGE",
        gp::DEFAULT_CLIENT_ASSERTION_MAX_AGE,
    )?;
    m.add(
        "RESERVED_ID_TOKEN_CLAIMS",
        RESERVED_ID_TOKEN_CLAIMS.to_vec(),
    )?;
    Ok(())
}
