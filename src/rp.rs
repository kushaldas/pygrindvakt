//! Bindings for `grindvakt::rp` - the relying-party (client) side of
//! OIDC / OAuth 2.0: discovery, authorization URL, code exchange, id_token
//! verification, userinfo, and `private_key_jwt` client assertions.
//!
//! Outbound HTTP goes through the `http` argument of the networked functions:
//! `None` for the built-in client, a `pygrindvakt.http.ReqwestClient`, or any
//! Python object implementing the `HttpClient` protocol (see `http.rs`).
//!
//! The Python API makes nonce omission explicit: `verify_id_token` refuses to
//! run without an expected nonce unless `unsafe_skip_nonce_check=True` is
//! passed. It also requires a signing-algorithm allowlist and makes additional
//! trusted audiences an explicit policy input.

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::time::Instant;

use async_trait::async_trait;
use grindvakt::callback as gcb;
use grindvakt::http::{HttpClient, HttpFetchResponse};
use grindvakt::Error as RsError;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyDict, PyList, PyMapping, PyModule, PySequence, PyTuple};

use grindvakt::jose_rs::algorithm::JwsAlgorithm;
use grindvakt::jose_rs::jwk::JwkSet;
use grindvakt::jwt as gj;
use grindvakt::metadata as gm;
use grindvakt::rp as grp;
use grindvakt::rp::ClientAuth;

use crate::convert::{from_py, new_submodule, to_py, warn};
use crate::errors::{
    config_err, config_from, err, escape_untrusted_quoted, escape_untrusted_text,
    is_invisible_format, with_code, with_code_retryable, AuthnError, InternalError,
    UnknownKeyError,
};
use crate::http::extract_http_client;
use crate::jwt::{drop_oct_keys, is_mac, jwks_from_py, prepare_mac_keys, KeySelection};
use crate::keys::SigningKey;
use crate::metadata::ProviderMetadata;

/// Render an optional string the way Python would (`'x'` / `None`).
fn opt_repr(v: Option<&str>) -> String {
    match v {
        Some(s) => format!("{s:?}"),
        None => "None".to_string(),
    }
}

// ---------------------------------------------------------------------------
// ProviderInfo
// ---------------------------------------------------------------------------

/// The minimal upstream-provider information the RP needs: issuer,
/// authorization and token endpoints, and optionally the userinfo endpoint
/// and JWKS URI.
///
/// Build one by hand for a statically configured provider, or with
/// `ProviderInfo.from_metadata(discover(http, issuer))`. Construction rejects
/// unsafe endpoint URLs before an authorization code or credential can be sent.
#[pyclass(
    module = "pygrindvakt.rp",
    name = "ProviderInfo",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct ProviderInfo {
    pub inner: grp::ProviderInfo,
    /// OIDC RP-Initiated Logout endpoint. Upstream `ProviderInfo` has no slot
    /// for it, so the binding carries it alongside.
    pub end_session_endpoint: Option<String>,
    /// The discovery document this value was built from
    /// (`ProviderInfo.from_metadata(discover(...))`). `None` for a hand-built
    /// `ProviderInfo`.
    pub metadata: Option<ProviderMetadata>,
    /// What `from_metadata` decided about the advertised
    /// `end_session_endpoint`, recorded then so `end_session_url` can explain
    /// a missing endpoint without re-deriving it. Not in `repr()`.
    end_session_outcome: EndSessionOutcome,
}

/// Outcome of the `end_session_endpoint` decision at build time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum EndSessionOutcome {
    /// Absent or JSON null, or a hand-built `ProviderInfo`.
    NotAdvertised,
    /// Advertised, valid, carried over.
    Accepted,
    /// Advertised as a string but unsafe or cross-origin; dropped.
    Rejected,
    /// Advertised with a non-string JSON value; dropped.
    InvalidType,
}

/// Same-origin test: scheme, host (the `url` crate lower-cases and IDNA-
/// normalises; a trailing dot is NOT stripped, so `op.example.` differs from
/// `op.example`) and effective port (default ports equal explicit ones).
fn same_origin(a: &str, b: &str) -> bool {
    let (Ok(a), Ok(b)) = (url::Url::parse(a), url::Url::parse(b)) else {
        return false;
    };
    a.scheme() == b.scheme()
        && a.host().is_some()
        && a.host() == b.host()
        && a.port_or_known_default().is_some()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// JSON type name for diagnostics (never the value itself).
fn json_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Best-effort `UserWarning`: a warnings filter of "error" must not make
/// login depend on logout.
fn warn_user(py: Python<'_>, text: &str) {
    let msg = std::ffi::CString::new(text.replace('\0', "?")).expect("NUL removed");
    let _ = PyErr::warn(
        py,
        &py.get_type::<pyo3::exceptions::PyUserWarning>(),
        &msg,
        1,
    );
}

/// Why an `end_session_endpoint` was refused.
enum EndSessionReject {
    /// Fails the shared scheme/userinfo/fragment/control-char rules.
    Unsafe(RsError),
    /// Safe, but not the issuer's origin and no opt-in.
    CrossOrigin,
}

/// Single validation point: the shared safety rules (upstream), then (unless
/// `allow_cross_origin`) same origin as the issuer, because `id_token_hint`
/// is sent to the endpoint's host.
fn check_end_session_endpoint(
    endpoint: &str,
    issuer: &str,
    allow_cross_origin: bool,
) -> Result<(), EndSessionReject> {
    for raw in [endpoint, issuer] {
        reject_reinterpreted_url_chars("end_session_endpoint", raw)
            .map_err(EndSessionReject::Unsafe)?;
    }
    grp::validate_service_endpoint_for_issuer("end_session_endpoint", endpoint, issuer)
        .map_err(EndSessionReject::Unsafe)?;
    if !allow_cross_origin && !same_origin(endpoint, issuer) {
        return Err(EndSessionReject::CrossOrigin);
    }
    Ok(())
}

/// `check_end_session_endpoint` as a raising Python-facing check.
fn validate_end_session_endpoint(
    endpoint: &str,
    issuer: &str,
    allow_cross_origin: bool,
) -> PyResult<()> {
    check_end_session_endpoint(endpoint, issuer, allow_cross_origin).map_err(|r| match r {
        EndSessionReject::Unsafe(e) => config_from(e),
        EndSessionReject::CrossOrigin => config_err(format!(
            "end_session_endpoint {endpoint:?} is on a different origin than the issuer \
             {issuer:?}; id_token_hint would be sent to that host. Pass \
             allow_cross_origin_end_session=True only if the OP legitimately logs out there"
        )),
    })
}

#[pymethods]
impl ProviderInfo {
    #[new]
    #[pyo3(signature = (issuer, authorization_endpoint, token_endpoint, userinfo_endpoint = None, jwks_uri = None, *, end_session_endpoint = None, allow_cross_origin_end_session = false))]
    fn new(
        issuer: String,
        authorization_endpoint: String,
        token_endpoint: String,
        userinfo_endpoint: Option<String>,
        jwks_uri: Option<String>,
        end_session_endpoint: Option<String>,
        allow_cross_origin_end_session: bool,
    ) -> PyResult<Self> {
        let inner = grp::ProviderInfo {
            issuer,
            authorization_endpoint,
            token_endpoint,
            userinfo_endpoint,
            jwks_uri,
        };
        inner.validate().map_err(config_from)?;
        if let Some(e) = &end_session_endpoint {
            validate_end_session_endpoint(e, &inner.issuer, allow_cross_origin_end_session)?;
        }
        Ok(Self {
            inner,
            end_session_outcome: if end_session_endpoint.is_some() {
                EndSessionOutcome::Accepted
            } else {
                EndSessionOutcome::NotAdvertised
            },
            end_session_endpoint,
            metadata: None,
        })
    }

    /// Build from a discovered `ProviderMetadata` document (the userinfo
    /// endpoint is `None` if the provider does not advertise one). An
    /// advertised `end_session_endpoint` is carried over; one that is unsafe
    /// or on a different origin than the issuer (unless
    /// `allow_cross_origin_end_session`) is dropped (`None`) with a
    /// `UserWarning`, so login never depends on logout; compare
    /// `end_session_endpoint` with `metadata.end_session_endpoint` to tell
    /// "not advertised" from "rejected". A non-string advertised value is
    /// likewise ignored with a `UserWarning`. The whole document stays
    /// reachable as `metadata`.
    #[staticmethod]
    #[pyo3(signature = (metadata, *, allow_cross_origin_end_session = false))]
    fn from_metadata(
        py: Python<'_>,
        metadata: &ProviderMetadata,
        allow_cross_origin_end_session: bool,
    ) -> PyResult<Self> {
        let inner = grp::ProviderInfo::from(metadata.inner.clone());
        inner.validate().map_err(config_from)?;
        // Login must not depend on logout: an advertised endpoint that fails
        // validation is dropped (with a UserWarning), never raised.
        let (end_session_endpoint, end_session_outcome) = match metadata
            .inner
            .extra
            .get("end_session_endpoint")
        {
            None | Some(serde_json::Value::Null) => (None, EndSessionOutcome::NotAdvertised),
            Some(serde_json::Value::String(e)) => {
                match check_end_session_endpoint(e, &inner.issuer, allow_cross_origin_end_session) {
                    Ok(()) => (Some(e.clone()), EndSessionOutcome::Accepted),
                    Err(reject) => {
                        let reason = match reject {
                            EndSessionReject::CrossOrigin => format!(
                                "end_session_endpoint {e:?} is on a different origin than the \
                                     issuer and was ignored; pass \
                                     allow_cross_origin_end_session=True to trust it"
                            ),
                            EndSessionReject::Unsafe(cause) => format!(
                                "end_session_endpoint {e:?} is unsafe ({cause}) and was ignored"
                            ),
                        };
                        warn_user(py, &reason);
                        (None, EndSessionOutcome::Rejected)
                    }
                }
            }
            Some(other) => {
                warn_user(
                    py,
                    &format!(
                        "end_session_endpoint has a non-string value ({}) and was ignored",
                        json_type_name(other)
                    ),
                );
                (None, EndSessionOutcome::InvalidType)
            }
        };
        Ok(Self {
            inner,
            end_session_endpoint,
            end_session_outcome,
            metadata: Some(metadata.clone()),
        })
    }

    #[getter]
    fn issuer(&self) -> &str {
        &self.inner.issuer
    }
    #[getter]
    fn authorization_endpoint(&self) -> &str {
        &self.inner.authorization_endpoint
    }
    #[getter]
    fn token_endpoint(&self) -> &str {
        &self.inner.token_endpoint
    }
    #[getter]
    fn userinfo_endpoint(&self) -> Option<&str> {
        self.inner.userinfo_endpoint.as_deref()
    }
    #[getter]
    fn jwks_uri(&self) -> Option<&str> {
        self.inner.jwks_uri.as_deref()
    }
    /// The OIDC RP-Initiated Logout endpoint, or `None`.
    #[getter]
    fn end_session_endpoint(&self) -> Option<&str> {
        self.end_session_endpoint.as_deref()
    }
    /// The discovery document this value was built from (a copy), or `None`
    /// for a hand-built `ProviderInfo`.
    ///
    /// WARNING: EVERY endpoint on this document (`userinfo_endpoint`,
    /// `token_endpoint`, `authorization_endpoint`, `jwks_uri`,
    /// `end_session_endpoint`, ...) is UNVALIDATED data from the OP
    /// (ADR 0004 section 3 exempts discovery). Never send credentials or
    /// tokens to them; use the validated properties on the `ProviderInfo`
    /// itself (`info.userinfo_endpoint`, `info.token_endpoint`, ...). The raw
    /// `end_session_endpoint` is kept only so you can diagnose a rejection.
    /// Not part of `repr()`.
    #[getter]
    fn metadata(&self) -> Option<ProviderMetadata> {
        self.metadata.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "ProviderInfo(issuer={:?}, authorization_endpoint={:?}, token_endpoint={:?}, \
             userinfo_endpoint={}, jwks_uri={}, end_session_endpoint={})",
            self.inner.issuer,
            self.inner.authorization_endpoint,
            self.inner.token_endpoint,
            opt_repr(self.inner.userinfo_endpoint.as_deref()),
            opt_repr(self.inner.jwks_uri.as_deref()),
            opt_repr(self.end_session_endpoint.as_deref())
        )
    }
}

// ---------------------------------------------------------------------------
// RpClient
// ---------------------------------------------------------------------------

fn auth_method_name(auth: &ClientAuth) -> &'static str {
    match auth {
        ClientAuth::None => "none",
        ClientAuth::ClientSecretBasic(_) => "client_secret_basic",
        ClientAuth::ClientSecretPost(_) => "client_secret_post",
        ClientAuth::PrivateKeyJwt(_) => "private_key_jwt",
    }
}

/// Resolve the token-endpoint authentication method from the constructor
/// arguments. The default mirrors tunnelbana's OIDC backend: `client_secret_basic`
/// when a secret is given, `none` otherwise. Every inconsistent combination is
/// rejected rather than silently ignored.
fn resolve_client_auth(
    auth_method: Option<&str>,
    client_secret: Option<String>,
    signing_key: Option<SigningKey>,
) -> PyResult<ClientAuth> {
    if matches!(client_secret.as_deref(), Some("")) {
        return Err(config_err("client_secret must not be empty"));
    }
    let method = match auth_method {
        Some(m) => m,
        None if client_secret.is_some() => "client_secret_basic",
        None => "none",
    };
    let auth = match method {
        "none" => {
            if client_secret.is_some() {
                return Err(config_err(
                    "auth_method='none' does not take a client_secret",
                ));
            }
            ClientAuth::None
        }
        "client_secret_basic" | "client_secret_post" => {
            let secret = client_secret.ok_or_else(|| {
                config_err(format!("auth_method={method:?} requires client_secret"))
            })?;
            if method == "client_secret_basic" {
                ClientAuth::ClientSecretBasic(secret)
            } else {
                ClientAuth::ClientSecretPost(secret)
            }
        }
        "private_key_jwt" => {
            if client_secret.is_some() {
                return Err(config_err(
                    "auth_method='private_key_jwt' does not take a client_secret",
                ));
            }
            let key = signing_key
                .clone()
                .ok_or_else(|| config_err("auth_method='private_key_jwt' requires signing_key"))?;
            ClientAuth::PrivateKeyJwt(key.inner)
        }
        other => {
            return Err(config_err(format!(
                "unknown auth_method {other:?}; expected one of \
                 'none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt'"
            )))
        }
    };
    if signing_key.is_some() && !matches!(auth, ClientAuth::PrivateKeyJwt(_)) {
        return Err(config_err(format!(
            "signing_key is only used with auth_method='private_key_jwt' (resolved method: {:?})",
            auth_method_name(&auth)
        )));
    }
    Ok(auth)
}

/// RP client configuration: `client_id`, `redirect_uri`, requested `scope`,
/// and how the client authenticates to the upstream token endpoint.
///
/// `auth_method` is one of `"none"`, `"client_secret_basic"`,
/// `"client_secret_post"` or `"private_key_jwt"`. When omitted it defaults to
/// `client_secret_basic` if `client_secret` is given, else `none`.
/// Inconsistent combinations (a secret method without `client_secret`,
/// `private_key_jwt` without `signing_key`, a secret or key that the chosen
/// method would ignore) raise `ConfigError` (also a `ValueError`).
///
/// SECURITY: `client_secret` is a credential. Load it from a secret store or
/// environment variable rather than embedding it in source, and note that it
/// is held in memory for the lifetime of the object. It is never included in
/// `repr()`.
#[pyclass(module = "pygrindvakt.rp", name = "RpClient", frozen, from_py_object)]
#[derive(Clone)]
pub struct RpClient {
    pub inner: grp::RpClient,
    /// Registered `post_logout_redirect_uris` (binding-side; the upstream
    /// client has no such field).
    pub post_logout_redirect_uris: Vec<String>,
    /// Registered alternative login `redirect_uris` accepted as per-call
    /// overrides (binding-side).
    pub redirect_uris: Vec<String>,
    /// Accept any syntactically valid per-call `redirect_uri` override.
    pub allow_unregistered_redirect_uri: bool,
}

/// Reject a backslash anywhere in a raw URL string. The `url` crate treats `\`
/// as `/` for special schemes, so `https://evil.example\@op.example.com`
/// parses with host `evil.example` and an empty username while the raw string
/// still ends in the trusted host. The message is fixed: the input is never
/// echoed.
pub(crate) fn reject_reinterpreted_url_chars(name: &str, raw: &str) -> Result<(), RsError> {
    if raw.contains('\\') {
        return Err(RsError::BadRequest(format!(
            "{name} must not contain a backslash"
        )));
    }
    Ok(())
}

/// Whitespace, control, bidi or invisible formatting character: the gate that
/// keeps a URI safe to echo into a `Location` header.
pub(crate) fn has_unsafe_uri_char(s: &str) -> bool {
    s.chars()
        .any(|c| c.is_whitespace() || c.is_control() || is_invisible_format(c))
}

/// Binding-side redirect URI syntax check; every redirect URI in this module
/// goes through it. Stricter than core's `validate_redirect_uri_syntax`, which
/// parses with the `url` crate (that strips tab/CR/LF) while the raw string is
/// what gets stored and echoed (for example into a `Location` header).
/// Rejects whitespace, control, bidi and invisible formatting characters,
/// then userinfo, then applies core's parse + no-fragment rule. The offending
/// value is never echoed. Custom-scheme URIs without an authority pass.
pub(crate) fn check_redirect_uri(uri: &str) -> Result<(), RsError> {
    reject_reinterpreted_url_chars("redirect_uri", uri)?;
    if has_unsafe_uri_char(uri) {
        return Err(RsError::BadRequest(
            "redirect_uri must not contain whitespace, control, bidi or invisible formatting characters"
                .into(),
        ));
    }
    if let Ok(u) = url::Url::parse(uri) {
        if !u.username().is_empty() || u.password().is_some() {
            return Err(RsError::BadRequest(
                "redirect_uri must not contain userinfo".into(),
            ));
        }
    }
    grp::validate_redirect_uri_syntax(uri)
}

/// Reject plain `http` to a non-loopback host. `https`, loopback `http` and
/// custom / private-use schemes (native apps) pass.
fn check_redirect_uri_transport(uri: &str) -> Result<(), RsError> {
    let u = url::Url::parse(uri)
        .map_err(|_| RsError::BadRequest(format!("redirect_uri {uri:?} is not an absolute URL")))?;
    if u.scheme() == "http" {
        let loopback = match u.host() {
            Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(a)) => a.is_loopback(),
            Some(url::Host::Ipv6(a)) => a.is_loopback(),
            None => false,
        };
        if !loopback {
            return Err(RsError::BadRequest(format!(
                "redirect_uri {uri:?} uses plain http to a non-loopback host; use https"
            )));
        }
    }
    Ok(())
}

impl RpClient {
    pub fn wrap(inner: grp::RpClient) -> Self {
        Self {
            inner,
            post_logout_redirect_uris: Vec::new(),
            redirect_uris: Vec::new(),
            allow_unregistered_redirect_uri: false,
        }
    }
}

#[pymethods]
impl RpClient {
    #[new]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (client_id, redirect_uri, *, scope = "openid profile email", client_secret = None, auth_method = None, signing_key = None, post_logout_redirect_uris = None, redirect_uris = None, allow_unregistered_redirect_uri = false))]
    fn new(
        client_id: String,
        redirect_uri: String,
        scope: &str,
        client_secret: Option<String>,
        auth_method: Option<&str>,
        signing_key: Option<SigningKey>,
        post_logout_redirect_uris: Option<Vec<String>>,
        redirect_uris: Option<Vec<String>>,
        allow_unregistered_redirect_uri: bool,
    ) -> PyResult<Self> {
        let redirect_uris = redirect_uris.unwrap_or_default();
        for uri in &redirect_uris {
            check_redirect_uri(uri).map_err(config_from)?;
            check_redirect_uri_transport(uri).map_err(config_from)?;
        }
        let post_logout_redirect_uris = post_logout_redirect_uris.unwrap_or_default();
        for uri in &post_logout_redirect_uris {
            check_redirect_uri(uri).map_err(config_from)?;
        }
        let auth = resolve_client_auth(auth_method, client_secret, signing_key)?;
        Ok(Self {
            inner: grp::RpClient {
                client_id,
                redirect_uri,
                auth,
                scope: scope.to_string(),
            },
            post_logout_redirect_uris,
            redirect_uris,
            allow_unregistered_redirect_uri,
        })
    }

    #[getter]
    fn client_id(&self) -> &str {
        &self.inner.client_id
    }
    #[getter]
    fn redirect_uri(&self) -> &str {
        &self.inner.redirect_uri
    }
    #[getter]
    fn scope(&self) -> &str {
        &self.inner.scope
    }
    /// Registered post-logout redirect URIs, as a tuple.
    #[getter]
    fn post_logout_redirect_uris<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        PyTuple::new(py, &self.post_logout_redirect_uris)
    }
    /// Registered alternative login redirect URIs, as a tuple.
    #[getter]
    fn redirect_uris<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        PyTuple::new(py, &self.redirect_uris)
    }
    /// Whether any syntactically valid per-call `redirect_uri` is accepted.
    #[getter]
    fn allow_unregistered_redirect_uri(&self) -> bool {
        self.allow_unregistered_redirect_uri
    }
    /// The token-endpoint authentication method as a string.
    #[getter]
    fn auth_method(&self) -> &'static str {
        auth_method_name(&self.inner.auth)
    }

    fn __repr__(&self) -> String {
        format!(
            "RpClient(client_id={:?}, redirect_uri={:?}, scope={:?}, auth_method={:?}, post_logout_redirect_uris={:?}, redirect_uris={:?}, allow_unregistered_redirect_uri={})",
            self.inner.client_id,
            self.inner.redirect_uri,
            self.inner.scope,
            auth_method_name(&self.inner.auth),
            self.post_logout_redirect_uris,
            self.redirect_uris,
            if self.allow_unregistered_redirect_uri { "True" } else { "False" }
        )
    }
}

// ---------------------------------------------------------------------------
// TokenSet
// ---------------------------------------------------------------------------

/// The result of a successful code exchange. `access_token`, `id_token`,
/// `token_type`, `refresh_token`, `expires_in` and `scope` are pulled out of
/// the response; `raw` is the full JSON body as a dict. `repr()` never prints
/// a token.
#[pyclass(module = "pygrindvakt.rp", name = "TokenSet", frozen, from_py_object)]
#[derive(Clone)]
pub struct TokenSet {
    pub inner: grp::TokenSet,
}

#[pymethods]
impl TokenSet {
    #[getter]
    fn access_token(&self) -> &str {
        &self.inner.access_token
    }
    #[getter]
    fn id_token(&self) -> &str {
        &self.inner.id_token
    }
    #[getter]
    fn token_type(&self) -> &str {
        &self.inner.token_type
    }
    /// The `refresh_token` member, or `None` when absent or not a string.
    /// SECURITY: a long-lived credential; store it encrypted and never log it.
    #[getter]
    fn refresh_token(&self) -> Option<&str> {
        self.inner.raw.get("refresh_token")?.as_str()
    }
    /// The `expires_in` member in seconds: a non-negative JSON integer (or
    /// an integral float) or a digits-only string, at most 10 years
    /// (315_360_000 s). `None` means "absent or not acceptable" (missing,
    /// negative, non-integer, garbage, longer than 10 years), NEVER "no
    /// expiry": apply your own default lifetime when it is `None` and do not
    /// treat `None` as unbounded.
    #[getter]
    fn expires_in(&self) -> Option<u64> {
        const MAX_EXPIRES_IN: u64 = 315_360_000;
        let secs = match self.inner.raw.get("expires_in")? {
            serde_json::Value::Number(n) => n.as_u64().or_else(|| {
                n.as_f64()
                    .filter(|f| f.is_finite() && *f >= 0.0 && f.fract() == 0.0 && *f < 1.8e19)
                    .map(|f| f as u64)
            }),
            serde_json::Value::String(s)
                if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) =>
            {
                s.parse().ok()
            }
            _ => None,
        };
        secs.filter(|n| *n <= MAX_EXPIRES_IN)
    }
    /// The `scope` member, or `None` when absent or not a string.
    #[getter]
    fn scope(&self) -> Option<&str> {
        self.inner.raw.get("scope")?.as_str()
    }
    /// The complete token-endpoint response as a dict.
    #[getter]
    fn raw<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner.raw)
    }

    fn __repr__(&self) -> String {
        format!(
            "TokenSet(token_type={:?}, access_token=<set>, id_token=<set>, refresh_token={})",
            self.inner.token_type,
            if self.refresh_token().is_some() {
                "<set>"
            } else {
                "None"
            },
        )
    }
}

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

/// Accept `extra` as either a `dict[str, str]` or a list of `(name, value)`
/// tuples (the list form allows repeated names).
fn extra_params(extra: Option<&Bound<'_, PyAny>>) -> PyResult<Vec<(String, String)>> {
    match extra {
        None => Ok(Vec::new()),
        Some(e) if e.is_none() => Ok(Vec::new()),
        Some(e) => {
            if let Ok(d) = e.cast::<PyDict>() {
                let mut out = Vec::with_capacity(d.len());
                for (k, v) in d.iter() {
                    out.push((k.extract::<String>()?, v.extract::<String>()?));
                }
                Ok(out)
            } else {
                e.extract::<Vec<(String, String)>>().map_err(|_| {
                    PyValueError::new_err(
                        "extra must be a dict[str, str] or a list of (str, str) tuples",
                    )
                })
            }
        }
    }
}

/// Return the upstream client, with `redirect_uri` swapped in when given.
///
/// SECURITY: an override is accepted only if it equals the client's
/// configured `redirect_uri` or one of its registered `redirect_uris`
/// (exact string match), or the client opted in with
/// `allow_unregistered_redirect_uri=True` (then it must still be valid and
/// not plain http to a non-loopback host). Otherwise `BadRequestError`.
fn effective_client(client: &RpClient, redirect_uri: Option<String>) -> PyResult<grp::RpClient> {
    let mut inner = client.inner.clone();
    if let Some(r) = redirect_uri {
        if r != inner.redirect_uri {
            let registered = client.redirect_uris.contains(&r);
            if !registered {
                if !client.allow_unregistered_redirect_uri {
                    return Err(err(RsError::BadRequest(
                        "redirect_uri override must be registered on the client \
                         (RpClient(redirect_uris=[...])) and match exactly; \
                         allow_unregistered_redirect_uri=True disables this check \
                         (only for RFC 7591 dynamic registrations, never with \
                         request-supplied values)"
                            .into(),
                    )));
                }
                check_redirect_uri(&r).map_err(err)?;
                check_redirect_uri_transport(&r).map_err(err)?;
            }
            inner.redirect_uri = r;
        }
    }
    Ok(inner)
}

/// Build the authorization request URL to redirect the user to.
///
/// `redirect_uri` overrides the client's configured value for this request
/// only; it must equal the client's `redirect_uri` or one of its registered
/// `redirect_uris` (exact match), or the client must be built with
/// `allow_unregistered_redirect_uri=True`. Never take it from request
/// parameters. The same value must be passed to `exchange_code`.
///
/// `state` and `nonce` must be fresh random values bound to the user's
/// session; `code_challenge` is the PKCE `S256` challenge
/// (`pygrindvakt.pkce.s256_challenge`). `extra` adds further query
/// parameters (e.g. `{"prompt": "login"}` or a signed `request` object).
#[pyfunction]
#[pyo3(signature = (provider, client, state, nonce, code_challenge = None, extra = None, *, redirect_uri = None))]
fn authorization_url(
    provider: &ProviderInfo,
    client: &RpClient,
    state: &str,
    nonce: &str,
    code_challenge: Option<&str>,
    extra: Option<&Bound<'_, PyAny>>,
    redirect_uri: Option<String>,
) -> PyResult<String> {
    let client = effective_client(client, redirect_uri)?;
    let extra = extra_params(extra)?;
    let extra_refs: Vec<(&str, &str)> = extra
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    grp::authorization_url(
        &provider.inner,
        &client,
        state,
        nonce,
        code_challenge,
        &extra_refs,
    )
    .map_err(err)
}

/// Build a signed request object (RFC 9101, "JAR") carrying the
/// authorization-request parameters as JWT claims, signed with `key`.
///
/// OpenID Federation automatic registration needs this: pass the result as
/// the `request` parameter (via `authorization_url(..., extra={"request": jar})`)
/// alongside the plain parameters. `key` must be one of the RP's published
/// client keys. The object is valid for 300 seconds and carries a `jti`.
/// `redirect_uri` overrides the client's value, as in `authorization_url`.
#[pyfunction]
#[pyo3(signature = (provider, client, key, state, nonce, code_challenge = None, *, redirect_uri = None))]
fn signed_request_object(
    provider: &ProviderInfo,
    client: &RpClient,
    key: &SigningKey,
    state: &str,
    nonce: &str,
    code_challenge: Option<&str>,
    redirect_uri: Option<String>,
) -> PyResult<String> {
    let client = effective_client(client, redirect_uri)?;
    grp::signed_request_object(
        &provider.inner,
        &client,
        &key.inner,
        state,
        nonce,
        code_challenge,
    )
    .map_err(err)
}

/// Start an authorization-code flow in one call.
///
/// Generates a fresh `state` and `nonce` (32 random bytes each) and, unless
/// `pkce=False`, a PKCE verifier (48 random bytes, 64 characters) with its
/// `S256` challenge. Returns a `BeginResult` named tuple
/// `(url, state, nonce, code_verifier)` (a real `tuple`: unpacking and
/// indexing work); `code_verifier` is `None` when `pkce=False`. Store `state`,
/// `nonce` and `code_verifier` (and `redirect_uri`, if overridden) in the
/// user's session. Its `repr()` redacts them.
///
/// Public clients (`auth_method="none"`) cannot disable PKCE: `pkce=False`
/// raises `ConfigError`. When `request_object_key` is given, a signed
/// request object (RFC 9101) is added as `extra["request"]`.
#[pyfunction]
#[pyo3(signature = (provider, client, *, extra = None, redirect_uri = None, pkce = true, request_object_key = None))]
fn begin<'py>(
    py: Python<'py>,
    provider: &ProviderInfo,
    client: &RpClient,
    extra: Option<&Bound<'_, PyAny>>,
    redirect_uri: Option<String>,
    pkce: bool,
    request_object_key: Option<&SigningKey>,
) -> PyResult<Bound<'py, PyAny>> {
    let client = effective_client(client, redirect_uri)?;
    // Refuse before generating anything: a public client must not run the
    // code flow without PKCE (upstream also enforces this; do not depend on it).
    if !pkce && matches!(client.auth, ClientAuth::None) {
        return Err(config_err("public clients must use S256 PKCE"));
    }
    let mut extra = extra_params(extra)?;
    let state = grindvakt::util::random_token(32);
    let nonce = grindvakt::util::random_token(32);
    let verifier = pkce.then(|| grindvakt::util::random_token(48));
    let challenge = verifier.as_deref().map(grindvakt::pkce::s256_challenge);
    if let Some(key) = request_object_key {
        let jar = grp::signed_request_object(
            &provider.inner,
            &client,
            &key.inner,
            &state,
            &nonce,
            challenge.as_deref(),
        )
        .map_err(err)?;
        extra.push(("request".to_string(), jar));
    }
    let extra_refs: Vec<(&str, &str)> = extra
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let url = grp::authorization_url(
        &provider.inner,
        &client,
        &state,
        &nonce,
        challenge.as_deref(),
        &extra_refs,
    )
    .map_err(err)?;
    begin_result_type(py)?.call1((url, state, nonce, verifier))
}

/// `BeginResult`: a `collections.namedtuple` subclass (module
/// `pygrindvakt.rp`) with a `__repr__` that redacts `state`, `nonce` and
/// `code_verifier` and strips the query from `url`. The class is defined in
/// embedded Python below: keep `BeginResult` in `python/pygrindvakt/rp.pyi`
/// in sync with it.
static BEGIN_RESULT: PyOnceLock<Py<PyAny>> = PyOnceLock::new();

fn begin_result_type<'py>(py: Python<'py>) -> PyResult<&'py Bound<'py, PyAny>> {
    BEGIN_RESULT
        .get_or_try_init(py, || {
            let globals = PyDict::new(py);
            py.run(
                cr##"
import collections

_Base = collections.namedtuple(
    "BeginResult", ["url", "state", "nonce", "code_verifier"], module="pygrindvakt.rp"
)


class BeginResult(_Base):
    __slots__ = ()
    __module__ = "pygrindvakt.rp"

    def __repr__(self):
        url, _state, _nonce, verifier = self
        if isinstance(url, str):
            base = url.split("#", 1)[0]
            if "?" in base:
                base = base.split("?", 1)[0] + "?…"
            url = base
        return "BeginResult(url=%r, state=<redacted>, nonce=<redacted>, code_verifier=%s)" % (
            url,
            "None" if verifier is None else "<redacted>",
        )


BeginResult.__doc__ = (
    "Result of rp.begin(): a named tuple (url, state, nonce, code_verifier). "
    "state, nonce and code_verifier are secrets: repr() redacts them and "
    "strips the query from url. code_verifier is None when pkce=False."
)
"##,
                Some(&globals),
                None,
            )?;
            Ok::<_, PyErr>(
                globals
                    .get_item("BeginResult")?
                    .expect("defined above")
                    .unbind(),
            )
        })
        .map(|t| t.bind(py))
}

/// Normalise the `aud` claim of a claims dict to a NON-EMPTY list of
/// strings: a non-empty string becomes `[string]`, a non-empty list of
/// non-empty strings is copied. Fails closed: a missing `aud`, `aud: []`,
/// `aud: ""` or an empty-string list member raises `BadRequestError`, so a
/// caller's `all(a in {CLIENT} for a in aud)` can never pass vacuously. Also
/// raises `BadRequestError` when `aud` is neither a string nor a list (or a
/// list member is not a string). Convenience only: `verify_id_token` returns
/// `aud` verbatim and the library itself performs the `aud` / `azp` checks;
/// `claims` is not modified.
#[pyfunction]
fn claims_audiences(claims: &Bound<'_, PyAny>) -> PyResult<Vec<String>> {
    let py = claims.py();
    let claims = claims.cast::<PyMapping>()?;
    let aud = match claims.get_item("aud") {
        Ok(v) => v,
        Err(e) if e.is_instance_of::<pyo3::exceptions::PyKeyError>(py) => {
            return Err(crate::errors::bad_request_err(
                "claims have no 'aud': an audience check cannot pass".to_string(),
            ))
        }
        Err(e) => return Err(e),
    };
    let empty_member = || {
        crate::errors::bad_request_err(
            "claims have an empty 'aud': an audience check cannot pass".to_string(),
        )
    };
    let type_name = |o: &Bound<'_, PyAny>| {
        o.get_type()
            .name()
            .map(|n| n.to_string())
            .unwrap_or_default()
    };
    // `to_cow` fails for lone surrogates; report a class, never the value.
    let text = |s: &Bound<'_, pyo3::types::PyString>| -> PyResult<String> {
        s.to_cow().map(|c| c.into_owned()).map_err(|_| {
            crate::errors::bad_request_err(
                "aud claim contains a string that is not valid Unicode (lone surrogate)"
                    .to_string(),
            )
        })
    };
    if let Ok(s) = aud.cast::<pyo3::types::PyString>() {
        let t = text(s)?;
        if t.is_empty() {
            return Err(empty_member());
        }
        return Ok(vec![t]);
    }
    let items: Vec<Bound<'_, PyAny>> = if let Ok(l) = aud.cast::<PyList>() {
        l.iter().collect()
    } else if let Ok(t) = aud.cast::<PyTuple>() {
        t.iter().collect()
    } else {
        return Err(crate::errors::bad_request_err(format!(
            "aud claim must be a string or a list of strings, got {}",
            escape_untrusted_text(&type_name(&aud), 64)
        )));
    };
    if items.is_empty() {
        return Err(empty_member());
    }
    items
        .iter()
        .map(|i| match i.cast::<pyo3::types::PyString>() {
            Ok(s) => {
                let t = text(s)?;
                if t.is_empty() {
                    Err(empty_member())
                } else {
                    Ok(t)
                }
            }
            Err(_) => Err(crate::errors::bad_request_err(format!(
                "aud claim list members must be strings, got {}",
                escape_untrusted_text(&type_name(i), 64)
            ))),
        })
        .collect()
}

/// Discover provider metadata from `issuer` (`/.well-known/openid-configuration`).
///
/// The issuer must be an `https` URL (plain `http` only for loopback hosts),
/// and the `issuer` in the returned document must match the requested one
/// exactly (OIDC Discovery section 4.3). `http` is `None` for the built-in
/// client, a `ReqwestClient`, or an object implementing the `HttpClient`
/// protocol.
#[pyfunction]
#[pyo3(signature = (http, issuer))]
fn discover(
    py: Python<'_>,
    http: Option<&Bound<'_, PyAny>>,
    issuer: String,
) -> PyResult<ProviderMetadata> {
    let (http, failures) = extract_http_client(http)?;
    discover_recorded(py, http, &failures, issuer).map(|d| d.metadata)
}

/// A discovery document together with what the fetch reported about itself.
struct Discovered {
    metadata: ProviderMetadata,
    /// The 200 response the document came from (headers empty when the client
    /// reports none).
    response: HttpFetchResponse,
    /// A response arrived and carried no header at all.
    headerless: bool,
}

/// Run `grp::discover_response` and keep the fetched body as `raw` on the
/// metadata; all validation stays upstream.
fn discover_recorded(
    py: Python<'_>,
    http: Arc<dyn HttpClient>,
    failures: &crate::http::Failures,
    issuer: String,
) -> PyResult<Discovered> {
    let probe = Arc::new(HeaderProbe {
        inner: http,
        saw_response: Default::default(),
        saw_headers: Default::default(),
    });
    let client: Arc<dyn HttpClient> = probe.clone();
    let r = crate::runtime::block_on(
        py,
        async move { grp::discover_response(&client, &issuer).await },
    )?;
    let grp::DiscoveryResponse {
        metadata, response, ..
    } = r.map_err(|e| failures.err(py, e))?;
    let raw = serde_json::from_slice::<serde_json::Value>(&response.body)
        .ok()
        .and_then(|v| match v {
            serde_json::Value::Object(m) => Some(m),
            _ => None,
        });
    let metadata = match raw {
        Some(raw) => ProviderMetadata::wrap_with_raw(metadata, raw),
        // Unreachable in practice (upstream parsed the same body); fall back
        // to the re-serialized document.
        None => {
            let raw = match metadata.to_json() {
                serde_json::Value::Object(m) => Some(m),
                _ => None,
            };
            match raw {
                Some(raw) => ProviderMetadata::wrap_with_raw(metadata, raw),
                None => ProviderMetadata::wrap(metadata),
            }
        }
    };
    Ok(Discovered {
        metadata,
        response,
        headerless: probe.headerless(),
    })
}

/// Library-controlled RP-Initiated Logout parameters.
const END_SESSION_RESERVED: &[&str] = &[
    "id_token_hint",
    "client_id",
    "post_logout_redirect_uri",
    "state",
    "logout_hint",
    "ui_locales",
];

fn non_empty(name: &str, v: Option<&str>) -> PyResult<()> {
    if v == Some("") {
        return Err(err(RsError::BadRequest(format!(
            "{name} must not be empty"
        ))));
    }
    Ok(())
}

/// Build the OIDC RP-Initiated Logout 1.0 request URL to redirect the user to.
///
/// Parameters are appended to the provider's `end_session_endpoint` (any
/// existing query is preserved) with proper encoding. `client` adds
/// `client_id`. `post_logout_redirect_uri` is accepted only if `client` is
/// given and the value exactly equals one of
/// `client.post_logout_redirect_uris` (pre-registration with exact match, as
/// RP-Initiated Logout requires); this prevents an open redirect when the
/// value comes from a request parameter. It must also be an absolute URL
/// without a fragment and registered with the OP.
/// `extra` (dict or list of pairs) may not contain the parameters controlled
/// by this function. Raises `ConfigError` if the provider has no
/// `end_session_endpoint` or it is unsafe, `BadRequestError` for invalid or
/// unregistered caller-supplied values.
#[pyfunction]
#[pyo3(signature = (provider, *, id_token_hint = None, client = None, post_logout_redirect_uri = None, state = None, logout_hint = None, ui_locales = None, extra = None))]
#[allow(clippy::too_many_arguments)]
fn end_session_url(
    provider: &ProviderInfo,
    id_token_hint: Option<&str>,
    client: Option<&RpClient>,
    post_logout_redirect_uri: Option<&str>,
    state: Option<&str>,
    logout_hint: Option<&str>,
    ui_locales: Option<&str>,
    extra: Option<&Bound<'_, PyAny>>,
) -> PyResult<String> {
    let endpoint = provider.end_session_endpoint.as_deref().ok_or_else(|| {
        let msg = match provider.end_session_outcome {
            EndSessionOutcome::Rejected => {
                "provider has no usable end_session_endpoint: the advertised value was rejected by \
                 ProviderInfo.from_metadata (cross-origin or unsafe; see the UserWarning emitted \
                 when the ProviderInfo was built, and info.metadata.end_session_endpoint for the \
                 raw, UNTRUSTED value (diagnostics only, never redirect to it))"
            }
            EndSessionOutcome::InvalidType => {
                "provider has no usable end_session_endpoint: the provider advertised a \
                 non-string end_session_endpoint, ignored by ProviderInfo.from_metadata (see the \
                 UserWarning emitted when the ProviderInfo was built, and \
                 info.metadata.end_session_endpoint for the raw, UNTRUSTED value (diagnostics \
                 only, never redirect to it))"
            }
            EndSessionOutcome::NotAdvertised | EndSessionOutcome::Accepted => {
                "provider has no usable end_session_endpoint: the provider does not advertise \
                 end_session_endpoint"
            }
        };
        err(RsError::Config(msg.into()))
    })?;
    // Origin binding was decided when the ProviderInfo was built (it may have
    // opted in); re-check only the shared safety rules here.
    validate_end_session_endpoint(endpoint, &provider.inner.issuer, true)?;
    let mut url = url::Url::parse(endpoint)
        .map_err(|e| config_err(format!("invalid end_session_endpoint: {e}")))?;
    if url
        .query_pairs()
        .any(|(k, _)| END_SESSION_RESERVED.contains(&k.as_ref()))
    {
        return Err(config_err(
            "end_session_endpoint query contains a library-controlled parameter",
        ));
    }
    for (name, v) in [
        ("id_token_hint", id_token_hint),
        ("post_logout_redirect_uri", post_logout_redirect_uri),
        ("state", state),
        ("logout_hint", logout_hint),
        ("ui_locales", ui_locales),
    ] {
        non_empty(name, v)?;
    }
    if let Some(uri) = post_logout_redirect_uri {
        check_redirect_uri(uri).map_err(err)?;
        // Exact match against the client's registration, never the caller's
        // say-so: otherwise a request-supplied value makes logout an open
        // redirect that also carries `id_token_hint`.
        let registered = client.is_some_and(|c| {
            c.post_logout_redirect_uris
                .iter()
                .any(|r| r.as_str() == uri)
        });
        if !registered {
            return Err(err(RsError::BadRequest(
                "post_logout_redirect_uri must be registered on the client \
                 (RpClient(post_logout_redirect_uris=[...])) and match exactly"
                    .into(),
            )));
        }
    }
    let extra = extra_params(extra)?;
    if let Some((k, _)) = extra
        .iter()
        .find(|(k, _)| END_SESSION_RESERVED.contains(&k.as_str()))
    {
        return Err(err(RsError::BadRequest(format!(
            "extra must not contain library-controlled parameter {k:?}"
        ))));
    }
    {
        let mut q = url.query_pairs_mut();
        if let Some(v) = id_token_hint {
            q.append_pair("id_token_hint", v);
        }
        if let Some(c) = client {
            q.append_pair("client_id", &c.inner.client_id);
        }
        if let Some(v) = post_logout_redirect_uri {
            q.append_pair("post_logout_redirect_uri", v);
        }
        if let Some(v) = state {
            q.append_pair("state", v);
        }
        if let Some(v) = logout_hint {
            q.append_pair("logout_hint", v);
        }
        if let Some(v) = ui_locales {
            q.append_pair("ui_locales", v);
        }
        for (k, v) in &extra {
            q.append_pair(k, v);
        }
    }
    Ok(url.into())
}

/// Fetch a JWKS document from `jwks_uri` for its associated `issuer` and
/// return it as a dict (`{"keys": [...]}`), ready for `verify_id_token`.
///
/// The issuer is required so loopback HTTP is allowed only for an explicitly
/// loopback HTTP development issuer.
///
/// A published JWK Set must not carry symmetric keys (OIDC Core section
/// 10.1): any `oct` key is dropped from the result and a `UserWarning` is
/// emitted, so a fetched set can never verify an `HS256` / `HS384` / `HS512`
/// token. MAC-signed ID tokens are verified with a key set you build from the
/// `client_secret` instead (see `verify_id_token`).
///
/// The warning is emitted once per call (no global dedup): Python's warnings
/// registry collapses identical messages per location by default, but under
/// `simplefilter("always")` or `"error"` it fires on every call. The returned
/// dict may therefore differ from the OP's published document; callers that
/// cache or diff it should use a warnings filter or `JwksCache`, which caches
/// the filtered set.
#[pyfunction]
#[pyo3(signature = (http, jwks_uri, issuer))]
fn fetch_jwks<'py>(
    py: Python<'py>,
    http: Option<&Bound<'py, PyAny>>,
    jwks_uri: String,
    issuer: String,
) -> PyResult<Bound<'py, PyAny>> {
    let (http, failures) = extract_http_client(http)?;
    let r = crate::runtime::block_on(py, async move {
        grp::fetch_jwks(&http, &jwks_uri, &issuer).await
    })?;
    let jwks = drop_published_oct_keys(py, r.map_err(|e| failures.err(py, e))?);
    to_py(py, &jwks)
}

/// Exchange an authorization `code` for tokens at the provider's token
/// endpoint, authenticating as configured on `client`. `code_verifier` is the
/// PKCE verifier matching the challenge sent in `authorization_url`.
///
/// If the authorization request used a `redirect_uri` override, pass the
/// same value here (RFC 6749 section 4.1.3); store it in the session with
/// the state, nonce and verifier.
///
/// A non-200 response raises `AuthnError` (generic message) with the
/// sanitized upstream details in `code` / `upstream_*`.
#[pyfunction]
#[pyo3(signature = (http, provider, client, code, code_verifier = None, *, redirect_uri = None))]
fn exchange_code(
    py: Python<'_>,
    http: Option<&Bound<'_, PyAny>>,
    provider: &ProviderInfo,
    client: &RpClient,
    code: String,
    code_verifier: Option<String>,
    redirect_uri: Option<String>,
) -> PyResult<TokenSet> {
    let (http, failures) = extract_http_client(http)?;
    let provider = provider.inner.clone();
    let client = effective_client(client, redirect_uri)?;
    let r = crate::runtime::block_on(py, async move {
        grp::exchange_code(&http, &provider, &client, &code, code_verifier.as_deref()).await
    })?;
    r.map(|inner| TokenSet { inner })
        .map_err(|e| failures.err(py, e))
}

/// Convert a Python int option to an unsigned seconds value.
fn seconds(name: &str, v: Option<i64>) -> PyResult<Option<u64>> {
    v.map(|v| u64::try_from(v).map_err(|_| config_err(format!("{name} must not be negative"))))
        .transpose()
}

fn parse_algorithms(algs: &[String]) -> PyResult<Vec<JwsAlgorithm>> {
    algs.iter()
        .map(|alg| {
            JwsAlgorithm::from_str(alg)
                .map_err(|e| config_err(format!("invalid JWS algorithm {alg:?}: {e}")))
        })
        .collect()
}

/// Refuse shared-secret algorithms for a key set that came from a published
/// JWKS (OIDC Core section 10.1: MAC keys derive from the `client_secret`,
/// and an OP must not publish symmetric keys). No override.
fn reject_published_mac(py: Python<'_>, algs: &[JwsAlgorithm]) -> PyResult<()> {
    if algs.iter().copied().any(is_mac) {
        return Err(with_code(
            py,
            config_err(
                "HS256/HS384/HS512 are not allowed with a JwksCache: an OP's published JWK Set \
                 never carries the key for MAC-signed ID tokens (OIDC Core section 10.1: the \
                 key is derived from the client_secret). Verify with rp.verify_id_token and a \
                 key set you build from the client_secret instead",
            ),
            "shared_secret_algorithm",
        ));
    }
    Ok(())
}

/// `jwt::drop_oct_keys` for a key set fetched from a published `jwks_uri`.
/// An OP must not publish symmetric keys (OIDC Core section 10.1), so they
/// are never used.
fn drop_published_oct_keys(py: Python<'_>, jwks: JwkSet) -> JwkSet {
    drop_oct_keys(
        py,
        jwks,
        "published JWKS",
        "OPs must not publish symmetric keys (OIDC Core section 10.1)",
    )
}

/// Enforce the nonce policy shared by `verify_id_token` and
/// `JwksCache.verify_id_token`.
fn check_nonce_policy(
    py: Python<'_>,
    expected_nonce: Option<&str>,
    unsafe_skip_nonce_check: bool,
) -> PyResult<()> {
    if expected_nonce.is_none() {
        if !unsafe_skip_nonce_check {
            return Err(AuthnError::new_err(
                "expected_nonce is required; pass unsafe_skip_nonce_check=True only for flows \
                 without a nonce",
            ));
        }
        warn(
            py,
            "verify_id_token: nonce check skipped (unsafe_skip_nonce_check=True); the id_token \
             is not bound to this authorization request",
        );
    }
    Ok(())
}

/// Everything `grindvakt::rp::verify_id_token_with` needs besides the key set
/// and the token itself.
struct IdTokenPolicy {
    algorithms: Vec<JwsAlgorithm>,
    trusted_additional_audiences: Vec<String>,
    leeway: Option<u64>,
    max_age: Option<u64>,
    acr_values: Option<Vec<String>>,
    access_token: Option<String>,
    require_at_hash: bool,
    authorization_code: Option<String>,
    require_c_hash: bool,
    strict_hashes: bool,
}

impl IdTokenPolicy {
    #[allow(clippy::too_many_arguments)]
    fn new(
        allowed_algorithms: &[String],
        trusted_additional_audiences: Option<Vec<String>>,
        leeway: Option<i64>,
        max_age: Option<i64>,
        acr_values: Option<Vec<String>>,
        access_token: Option<String>,
        require_at_hash: bool,
        authorization_code: Option<String>,
        require_c_hash: bool,
        strict_hashes: bool,
    ) -> PyResult<Self> {
        let mut policy = Self {
            algorithms: parse_algorithms(allowed_algorithms)?,
            trusted_additional_audiences: trusted_additional_audiences.unwrap_or_default(),
            leeway: seconds("leeway", leeway)?,
            max_age: seconds("max_age", max_age)?,
            acr_values,
            access_token,
            require_at_hash,
            authorization_code,
            require_c_hash,
            strict_hashes,
        };
        // Fail on configuration errors before any key-set fetch; upstream
        // repeats these checks.
        if policy.require_at_hash && policy.access_token.is_none() {
            return Err(config_err(
                "require_at_hash needs an access_token to check against",
            ));
        }
        if policy.require_c_hash && policy.authorization_code.is_none() {
            return Err(config_err(
                "require_c_hash needs an authorization_code to check against",
            ));
        }
        // `strict_hashes` requires the claim whenever the value to bind it to
        // is in hand (blocks token substitution by omission). Applied after
        // the checks above so explicit-flag misuse still raises.
        policy.require_at_hash |= policy.strict_hashes && policy.access_token.is_some();
        policy.require_c_hash |= policy.strict_hashes && policy.authorization_code.is_some();
        if policy.leeway.is_some_and(|l| l > grp::MAX_ID_TOKEN_LEEWAY) {
            return Err(config_err(format!(
                "id_token leeway must be at most {} seconds",
                grp::MAX_ID_TOKEN_LEEWAY
            )));
        }
        if policy.acr_values.as_ref().is_some_and(Vec::is_empty) {
            return Err(config_err("acr_values must not be empty when set"));
        }
        Ok(policy)
    }

    fn verify(
        &self,
        py: Python<'_>,
        jwks: &JwkSet,
        id_token: &str,
        issuer: &str,
        client_id: &str,
        expected_nonce: Option<&str>,
    ) -> PyResult<Py<PyAny>> {
        let jwks = &*prepare_mac_keys(py, jwks, id_token, &self.algorithms, KeySelection::Named)?;
        let trusted = self
            .trusted_additional_audiences
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let acr = self
            .acr_values
            .as_ref()
            .map(|v| v.iter().map(String::as_str).collect::<Vec<_>>());
        // Unless `strict_hashes`, `allow_unchecked_hashes` keeps
        // `verify_id_token`'s historical behaviour: an at_hash / c_hash is
        // checked when the matching value is given and ignored otherwise.
        let mut options = grp::IdTokenOptions::new();
        if !self.strict_hashes {
            options = options.allow_unchecked_hashes();
        }
        if let Some(v) = self.leeway {
            options = options.with_leeway(v);
        }
        if let Some(v) = self.max_age {
            options = options.with_max_age(v);
        }
        if let Some(v) = acr.as_deref() {
            options = options.with_acr_values(v);
        }
        if let Some(v) = self.access_token.as_deref() {
            options = options.with_access_token(v);
        }
        if self.require_at_hash {
            options = options.with_required_at_hash();
        }
        if let Some(v) = self.authorization_code.as_deref() {
            options = options.with_authorization_code(v);
        }
        if self.require_c_hash {
            options = options.with_required_c_hash();
        }
        let claims = grp::verify_id_token_with(
            jwks,
            id_token,
            issuer,
            client_id,
            expected_nonce,
            &self.algorithms,
            &trusted,
            &options,
        )
        .map_err(err)?;
        Ok(to_py(py, &claims)?.unbind())
    }
}

/// Verify an `id_token` against the provider JWKS (a dict `{"keys": [...]}`
/// or a `JwksCache`), `issuer`, audience `client_id`, and `expected_nonce`;
/// `sub`, `exp`, and `iat` are required. The protected algorithm must be
/// explicitly allowed; all other audiences must be explicitly trusted and
/// multi-audience tokens must name this client in `azp`. Returns the validated
/// claims as a dict.
///
/// `expected_nonce` is the nonce this RP sent in the authorization request.
/// Passing `None` is refused with `AuthnError` unless
/// `unsafe_skip_nonce_check=True` is given as well, which disables the nonce
/// check entirely and emits a `UserWarning`.
///
/// SECURITY: only skip the nonce check for flows that genuinely carry no
/// nonce (e.g. a pure OAuth 2.0 flow that still returns an id_token). Skipping
/// it for the standard code flow allows id_token replay.
///
/// `HS256` / `HS384` / `HS512` ID tokens are MAC'd with a key derived from the
/// `client_secret` (OIDC Core section 10.1), never from the OP's JWK Set.
/// Verify them with a key set you build yourself, for example
/// `{"keys": [{"kty": "oct", "k": <base64url(client_secret)>}]}`; the key
/// must be at least as long as the hash output (32 / 48 / 64 bytes, RFC 7518
/// section 3.2), else `ConfigError(code="weak_shared_secret")`. A `JwksCache`
/// as `jwks` with an `HS*` algorithm is refused
/// (`ConfigError(code="shared_secret_algorithm")`); `none` is never accepted.
///
/// Optional extra checks (keyword-only, all off by default):
///
/// * `leeway`: clock-skew tolerance in seconds for `exp` / `nbf` / `iat` and
///   the future-`auth_time` check (default 60; above 300 is `ConfigError`).
/// * `max_age`: requires a numeric `auth_time` claim no older than `max_age`
///   seconds (`iat` is not used; a missing or non-numeric `auth_time` is an
///   `AuthnError`; leeway is not added).
/// * `acr_values`: the `acr` claim must be present and in this list.
/// * `access_token` / `authorization_code`: validate `at_hash` / `c_hash`
///   when the id_token carries one. `require_at_hash` / `require_c_hash`
///   additionally reject tokens without the claim (they need the matching
///   value, else `ConfigError`). An `EdDSA` token carrying a hash claim
///   cannot be checked (`CryptoError`).
/// * `strict_hashes`: reject (`AuthnError`) an id_token carrying `at_hash` /
///   `c_hash` that cannot be checked (no matching `access_token` /
///   `authorization_code`), and require `at_hash` / `c_hash` whenever
///   `access_token` / `authorization_code` is passed (as if `require_*_hash`
///   were set). Without it such a claim is ignored. Code-flow callers who pass
///   `access_token` but whose OP omits `at_hash` must leave it off. An
///   `EdDSA` token cannot satisfy the requirement (`AuthnError` if the claim
///   is absent, `CryptoError` if present).
#[pyfunction]
#[pyo3(signature = (jwks, id_token, issuer, client_id, expected_nonce, allowed_algorithms,
                    trusted_additional_audiences = None, unsafe_skip_nonce_check = false, *,
                    leeway = None, max_age = None, acr_values = None, access_token = None,
                    require_at_hash = false, authorization_code = None, require_c_hash = false,
                    strict_hashes = false))]
// These arguments are deliberately explicit security-policy inputs in the
// public Python API; hiding them in an options bag would make unsafe defaults
// easier to overlook.
#[allow(clippy::too_many_arguments)]
fn verify_id_token<'py>(
    py: Python<'py>,
    jwks: &Bound<'py, PyAny>,
    id_token: &str,
    issuer: &str,
    client_id: &str,
    expected_nonce: Option<&str>,
    allowed_algorithms: Vec<String>,
    trusted_additional_audiences: Option<Vec<String>>,
    unsafe_skip_nonce_check: bool,
    leeway: Option<i64>,
    max_age: Option<i64>,
    acr_values: Option<Vec<String>>,
    access_token: Option<String>,
    require_at_hash: bool,
    authorization_code: Option<String>,
    require_c_hash: bool,
    strict_hashes: bool,
) -> PyResult<Bound<'py, PyAny>> {
    check_nonce_policy(py, expected_nonce, unsafe_skip_nonce_check)?;
    let policy = IdTokenPolicy::new(
        &allowed_algorithms,
        trusted_additional_audiences,
        leeway,
        max_age,
        acr_values,
        access_token,
        require_at_hash,
        authorization_code,
        require_c_hash,
        strict_hashes,
    );
    let set = JwksSource::from_py(jwks)?;
    let policy = policy?;
    set.check_algorithms(py, &policy.algorithms)?;
    let set = set.resolve(py, id_token, issuer)?;
    Ok(policy
        .verify(py, &set, id_token, issuer, client_id, expected_nonce)?
        .into_bound(py))
}

// ---------------------------------------------------------------------------
// JwksCache
// ---------------------------------------------------------------------------

/// A JWKS argument: a literal key set or a `JwksCache`.
enum JwksSource<'py> {
    Set(Arc<JwkSet>),
    Cache(Bound<'py, JwksCache>),
}

impl<'py> JwksSource<'py> {
    fn from_py(obj: &Bound<'py, PyAny>) -> PyResult<Self> {
        if let Ok(cache) = obj.cast::<JwksCache>() {
            return Ok(Self::Cache(cache.clone()));
        }
        Ok(Self::Set(Arc::new(jwks_from_py(obj)?)))
    }

    /// A cache is bound to one issuer. `issuer` is the issuer the caller will
    /// verify against, and it must equal the cache's issuer, so keys of one
    /// provider can never vouch for another provider's `iss`. Call this
    /// before any network request.
    fn check_issuer(&self, issuer: &str) -> PyResult<()> {
        match self {
            Self::Cache(cache) if cache.get().issuer != issuer => Err(config_err(
                "JwksCache issuer does not match the issuer argument",
            )),
            _ => Ok(()),
        }
    }

    /// A cache is a published JWKS: shared-secret algorithms are refused for
    /// it. Call this before any network request.
    fn check_algorithms(&self, py: Python<'_>, algs: &[JwsAlgorithm]) -> PyResult<()> {
        match self {
            Self::Cache(_) => reject_published_mac(py, algs),
            Self::Set(_) => Ok(()),
        }
    }

    /// The key set to verify `token` against (for a cache: refreshed once if
    /// the token's `kid` is unknown). Rejects an issuer mismatch first.
    fn resolve(&self, py: Python<'py>, token: &str, issuer: &str) -> PyResult<Arc<JwkSet>> {
        self.check_issuer(issuer)?;
        match self {
            Self::Set(set) => Ok(set.clone()),
            Self::Cache(cache) => cache.get().resolve_for_token(py, token),
        }
    }
}

/// Monotonic seconds since first use; the default cache clock. Unaffected by
/// wall-clock changes and valid across `fork`.
fn monotonic_now() -> f64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_secs_f64()
}

struct CacheEntry {
    jwks: Arc<JwkSet>,
    expires_at: f64,
}

#[derive(Default)]
struct CacheState {
    entry: Option<Arc<CacheEntry>>,
    /// Clock reading of the latest fetch attempt (successful or not).
    last_attempt: Option<f64>,
}

/// Wraps the fetch client to note whether any response carried headers.
struct HeaderProbe {
    inner: Arc<dyn HttpClient>,
    saw_response: std::sync::atomic::AtomicBool,
    saw_headers: std::sync::atomic::AtomicBool,
}

impl HeaderProbe {
    fn note(
        &self,
        r: grindvakt::Result<HttpFetchResponse>,
    ) -> grindvakt::Result<HttpFetchResponse> {
        use std::sync::atomic::Ordering::Relaxed;
        if let Ok(resp) = &r {
            self.saw_response.store(true, Relaxed);
            if !resp.headers.is_empty() {
                self.saw_headers.store(true, Relaxed);
            }
        }
        r
    }

    /// A response arrived and none of them had any header.
    fn headerless(&self) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        self.saw_response.load(Relaxed) && !self.saw_headers.load(Relaxed)
    }
}

#[async_trait]
impl HttpClient for HeaderProbe {
    async fn get(&self, url: &str) -> grindvakt::Result<HttpFetchResponse> {
        let r = self.inner.get(url).await;
        self.note(r)
    }

    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        headers: &[(String, String)],
    ) -> grindvakt::Result<HttpFetchResponse> {
        let r = self.inner.post_form(url, form, headers).await;
        self.note(r)
    }

    async fn get_with_headers(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> grindvakt::Result<HttpFetchResponse> {
        let r = self.inner.get_with_headers(url, headers).await;
        self.note(r)
    }

    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
        headers: &[(String, String)],
    ) -> grindvakt::Result<HttpFetchResponse> {
        let r = self.inner.post_json(url, body, headers).await;
        self.note(r)
    }
}

/// RAII token for the single in-flight fetch; see `begin_flight`. Shared by
/// `JwksCache` and `DiscoveryCache`.
struct Flight<'a> {
    busy: &'a Mutex<bool>,
    done: &'a Condvar,
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        let mut busy = self.busy.lock().unwrap_or_else(|e| e.into_inner());
        *busy = false;
        self.done.notify_one();
    }
}

/// Clock reading: the injected `_now` hook, else the monotonic clock. A hook
/// that raises or returns a non-float falls back to the monotonic clock.
fn clock_now(clock: &Option<Py<PyAny>>) -> f64 {
    match clock {
        Some(clock) => Python::attach(|py| clock.call0(py).and_then(|v| v.extract::<f64>(py)))
            .unwrap_or_else(|_| monotonic_now()),
        None => monotonic_now(),
    }
}

/// Wait (with the GIL released, because the holder needs the GIL to run a
/// Python HTTP adapter) until no other thread is fetching, then become the
/// fetching thread. The wait is bounded by `timeout` (real time, not the
/// injected test clock); on expiry it raises `InternalError(code=timeout_code)`
/// whose message names `what`. The holder is never interrupted and still clears
/// the flight when it finishes.
fn begin_flight<'a>(
    py: Python<'_>,
    busy: &'a Mutex<bool>,
    done: &'a Condvar,
    timeout: std::time::Duration,
    what: &str,
    timeout_code: &str,
) -> PyResult<Flight<'a>> {
    let acquired = py.detach(|| {
        // `None`: the timeout is too large to represent; wait unbounded.
        let deadline = std::time::Instant::now().checked_add(timeout);
        let mut guard = busy.lock().unwrap_or_else(|e| e.into_inner());
        while *guard {
            let wait = match deadline {
                None => std::time::Duration::from_secs(3600),
                Some(d) => {
                    let left = d.saturating_duration_since(std::time::Instant::now());
                    if left.is_zero() {
                        return false;
                    }
                    left
                }
            };
            guard = done
                .wait_timeout(guard, wait)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        *guard = true;
        true
    });
    if !acquired {
        let msg = format!(
            "timed out after {}s waiting for another thread's {what}",
            timeout.as_secs_f64()
        );
        return Err(with_code(py, InternalError::new_err(msg), timeout_code));
    }
    Ok(Flight { busy, done })
}

/// Validate and convert a `fetch_timeout` argument (seconds).
fn parse_fetch_timeout(fetch_timeout: f64) -> PyResult<std::time::Duration> {
    const MSG: &str = "fetch_timeout must be a finite number of seconds, at least 1e-9";
    if !(fetch_timeout.is_finite() && fetch_timeout > 0.0) {
        return Err(config_err(MSG));
    }
    // Absurdly large values saturate instead of panicking.
    let d =
        std::time::Duration::try_from_secs_f64(fetch_timeout).unwrap_or(std::time::Duration::MAX);
    if d.is_zero() {
        return Err(config_err(MSG));
    }
    Ok(d)
}

/// Defaults of the `JwksCache` constructor, defined once: the pyo3 signature
/// and `DiscoveryCache::jwks` (which builds its `JwksCache` with them) both use
/// these, so they cannot drift.
const JWKS_DEFAULT_TTL: i64 = 3600;
const JWKS_MIN_TTL: i64 = 60;
const JWKS_MAX_TTL: i64 = 86400;
const JWKS_MIN_REFRESH_INTERVAL: i64 = 30;
const JWKS_FETCH_TIMEOUT: f64 = 45.0;

/// A caching JWK Set fetcher for one issuer.
///
/// Holds the key set fetched from `jwks_uri` and refetches it when it
/// expires. The lifetime is the response's `Cache-Control: max-age` minus
/// `Age` when present, else `default_ttl`, clamped to `[min_ttl, max_ttl]`
/// (so `no-store` / `no-cache` / `max-age=0` are floored to `min_ttl`; set
/// `min_ttl=0` to leave them uncached). Cache-Control is honoured only when
/// the `HttpClient` reports response headers: the built-in client (`None` /
/// `ReqwestClient`) always does, a Python adapter must return them (see
/// `HttpFetchResponse`); otherwise `default_ttl` applies and a `UserWarning`
/// is emitted on the first fetch. An expired set is never served: a
/// failed refetch raises. Concurrent callers share a single fetch.
///
/// `fetch_timeout` (seconds, at least 1e-9, default 45: the built-in client's
/// 30s request timeout plus margin) bounds how long a thread WAITS for
/// another thread's in-flight fetch; on expiry the waiter raises
/// `InternalError(code="jwks_fetch_timeout")`. It does not interrupt the
/// thread running the fetch: a Python `HttpClient` adapter must set its own
/// network timeouts, and a stalled adapter still stalls its own caller (the
/// built-in `ReqwestClient` has a 30s request timeout). The fetch carries on
/// and its result is cached when it finishes.
///
/// Symmetric (`oct`) keys in the fetched document are dropped with a
/// `UserWarning` (once per fetch): an OP must not publish them (OIDC Core
/// section 10.1). `verify_id_token` refuses `HS256` / `HS384` / `HS512` in
/// `allowed_algorithms` with `ConfigError(code="shared_secret_algorithm")`
/// and no override: use `rp.verify_id_token` with a key set built from the
/// `client_secret` for those.
///
/// `verify_id_token` refreshes the set at most once when the token's `kid` is
/// not in it (key rotation), but no more often than `min_refresh_interval`
/// seconds after the previous fetch attempt; if the `kid` is still unknown it
/// raises `UnknownKeyError`. The cache is plain in-process memory: it stays
/// valid in a forked child, but fork only while no other thread is inside a
/// cache call.
///
/// `_now` is a private test hook: a zero-argument callable returning the
/// clock in seconds.
#[pyclass(module = "pygrindvakt.rp", name = "JwksCache", frozen)]
pub struct JwksCache {
    http: Option<Py<PyAny>>,
    jwks_uri: String,
    issuer: String,
    default_ttl: u64,
    min_ttl: u64,
    max_ttl: u64,
    min_refresh_interval: u64,
    fetch_timeout: std::time::Duration,
    clock: Option<Py<PyAny>>,
    state: RwLock<CacheState>,
    flight: Mutex<bool>,
    flight_done: Condvar,
    /// The no-response-headers warning is emitted once per cache.
    warned_no_headers: std::sync::atomic::AtomicBool,
}

impl JwksCache {
    /// Validate the arguments and build a cache. Shared by the Python
    /// constructor and `DiscoveryCache::jwks`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build(
        http: Option<&Bound<'_, PyAny>>,
        jwks_uri: String,
        issuer: String,
        default_ttl: i64,
        min_ttl: i64,
        max_ttl: i64,
        min_refresh_interval: i64,
        fetch_timeout: f64,
        clock: Option<Py<PyAny>>,
    ) -> PyResult<Self> {
        // Validate the client and the URLs now rather than on first use.
        extract_http_client(http)?;
        reject_reinterpreted_url_chars("issuer", &issuer).map_err(config_from)?;
        reject_reinterpreted_url_chars("jwks_uri", &jwks_uri).map_err(config_from)?;
        grp::validate_issuer(&issuer).map_err(config_from)?;
        grp::validate_service_endpoint_for_issuer("jwks_uri", &jwks_uri, &issuer)
            .map_err(config_from)?;
        let get = |n: &str, v: i64| seconds(n, Some(v)).map(Option::unwrap_or_default);
        let (default_ttl, min_ttl, max_ttl) = (
            get("default_ttl", default_ttl)?,
            get("min_ttl", min_ttl)?,
            get("max_ttl", max_ttl)?,
        );
        if min_ttl > max_ttl {
            return Err(config_err("min_ttl must not exceed max_ttl"));
        }
        let fetch_timeout = parse_fetch_timeout(fetch_timeout)?;
        Ok(Self {
            http: http.filter(|h| !h.is_none()).map(|h| h.clone().unbind()),
            jwks_uri,
            issuer,
            default_ttl,
            min_ttl,
            max_ttl,
            min_refresh_interval: get("min_refresh_interval", min_refresh_interval)?,
            fetch_timeout,
            clock,
            state: RwLock::default(),
            flight: Mutex::new(false),
            flight_done: Condvar::new(),
            warned_no_headers: Default::default(),
        })
    }

    fn now(&self) -> f64 {
        clock_now(&self.clock)
    }

    fn snapshot(&self) -> Option<Arc<CacheEntry>> {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .entry
            .clone()
    }

    fn valid_entry(&self, now: f64) -> Option<Arc<CacheEntry>> {
        self.snapshot().filter(|e| now < e.expires_at)
    }

    /// Become the fetching thread; see the free `begin_flight`. A waiter that
    /// times out raises `InternalError(code="jwks_fetch_timeout")`.
    fn begin_flight(&self, py: Python<'_>) -> PyResult<Flight<'_>> {
        begin_flight(
            py,
            &self.flight,
            &self.flight_done,
            self.fetch_timeout,
            "JWKS fetch",
            "jwks_fetch_timeout",
        )
    }

    fn rate_limited(&self, now: f64) -> bool {
        let last = self
            .state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .last_attempt;
        last.is_some_and(|t| now - t < self.min_refresh_interval as f64)
    }

    /// Fetch and store the key set. The caller holds the flight.
    fn fetch(&self, py: Python<'_>) -> PyResult<Arc<CacheEntry>> {
        let attempt = self.now();
        self.state
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .last_attempt = Some(attempt);
        // A fresh client (and `Failures` slot) per fetch, so a transport
        // error is chained to this call's failure only.
        let (http, failures) = extract_http_client(self.http.as_ref().map(|h| h.bind(py)))?;
        let (uri, issuer) = (self.jwks_uri.clone(), self.issuer.clone());
        let probe = Arc::new(HeaderProbe {
            inner: http,
            saw_response: Default::default(),
            saw_headers: Default::default(),
        });
        let client: Arc<dyn HttpClient> = probe.clone();
        let r = crate::runtime::block_on(py, async move {
            grp::fetch_jwks_response(&client, &uri, &issuer).await
        })?;
        let resp = r.map_err(|e| failures.err(py, e))?;
        if probe.headerless()
            && !self
                .warned_no_headers
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            warn(
                py,
                &format!(
                    "this HttpClient reports no response headers; Cache-Control is ignored and \
                     default_ttl ({}s) applies; return headers from your HttpClient or lower \
                     default_ttl/max_ttl",
                    self.default_ttl
                ),
            );
        }
        let ttl = resp
            .cache_ttl_secs()
            .unwrap_or(self.default_ttl)
            .clamp(self.min_ttl, self.max_ttl);
        let entry = Arc::new(CacheEntry {
            jwks: Arc::new(drop_published_oct_keys(py, resp.jwks)),
            expires_at: self.now() + ttl as f64,
        });
        self.state.write().unwrap_or_else(|e| e.into_inner()).entry = Some(entry.clone());
        Ok(entry)
    }

    /// The current key set, fetching it first if there is none or it expired.
    fn ensure(&self, py: Python<'_>) -> PyResult<Arc<CacheEntry>> {
        if let Some(e) = self.valid_entry(self.now()) {
            return Ok(e);
        }
        let _flight = self.begin_flight(py)?;
        // Another thread may have fetched while we waited.
        if let Some(e) = self.valid_entry(self.now()) {
            return Ok(e);
        }
        self.fetch(py)
    }

    fn resolve_for_token(&self, py: Python<'_>, token: &str) -> PyResult<Arc<JwkSet>> {
        let entry = self.ensure(py)?;
        // An unreadable header is left to the verifier's own error.
        let Some(kid) = gj::peek_header(token).ok().and_then(|h| h.kid) else {
            return Ok(entry.jwks.clone());
        };
        if !kid_unknown(&entry.jwks, &kid) {
            return Ok(entry.jwks.clone());
        }
        let _flight = self.begin_flight(py)?;
        // Re-select through `valid_entry`: the wait may have outlived the old
        // entry, or another thread may have stored a zero-TTL set. Never
        // verify with an expired snapshot; fetch again instead.
        let now = self.now();
        let entry = match self.valid_entry(now) {
            // Another thread refreshed while we waited.
            Some(current) if !Arc::ptr_eq(&current, &entry) => current,
            // Rate-limited: keep the (still valid) entry we already have.
            Some(current) if self.rate_limited(now) => current,
            _ => self.fetch(py)?,
        };
        if kid_unknown(&entry.jwks, &kid) {
            return Err(UnknownKeyError::new_err(
                "token kid does not name a key in the issuer's JWK Set (refresh may have been skipped by the minimum refresh interval)",
            ));
        }
        Ok(entry.jwks.clone())
    }
}

/// The set has keys with a `kid` and none of them is `kid`.
fn kid_unknown(jwks: &JwkSet, kid: &str) -> bool {
    jwks.keys.iter().any(|k| k.kid.is_some())
        && !jwks.keys.iter().any(|k| k.kid.as_deref() == Some(kid))
}

#[pymethods]
impl JwksCache {
    #[new]
    #[pyo3(signature = (http, jwks_uri, issuer, *, default_ttl = JWKS_DEFAULT_TTL,
                        min_ttl = JWKS_MIN_TTL, max_ttl = JWKS_MAX_TTL,
                        min_refresh_interval = JWKS_MIN_REFRESH_INTERVAL,
                        fetch_timeout = JWKS_FETCH_TIMEOUT, _now = None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        http: Option<&Bound<'_, PyAny>>,
        jwks_uri: String,
        issuer: String,
        default_ttl: i64,
        min_ttl: i64,
        max_ttl: i64,
        min_refresh_interval: i64,
        fetch_timeout: f64,
        _now: Option<Py<PyAny>>,
    ) -> PyResult<Self> {
        Self::build(
            http,
            jwks_uri,
            issuer,
            default_ttl,
            min_ttl,
            max_ttl,
            min_refresh_interval,
            fetch_timeout,
            _now,
        )
    }
    #[getter]
    fn jwks_uri(&self) -> &str {
        &self.jwks_uri
    }

    #[getter]
    fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Seconds a thread waits for another thread's in-flight fetch.
    #[getter]
    fn fetch_timeout(&self) -> f64 {
        self.fetch_timeout.as_secs_f64()
    }

    fn __repr__(&self) -> String {
        format!(
            "JwksCache(jwks_uri={:?}, issuer={:?})",
            self.jwks_uri, self.issuer
        )
    }

    /// The cached key set as a dict (`{"keys": [...]}`), fetching it first if
    /// none is cached or it expired. Raises if that fetch fails; an expired
    /// set is never returned.
    fn jwks<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let entry = self.ensure(py)?;
        to_py(py, &*entry.jwks)
    }

    /// Force a refetch. The first fetch always happens; afterwards a call
    /// within `min_refresh_interval` seconds of the previous fetch attempt is
    /// a silent no-op. A failed fetch raises and keeps the cached set.
    fn refresh(&self, py: Python<'_>) -> PyResult<()> {
        // A fetch in progress has already set `last_attempt`, so a rate-limited
        // call returns at once instead of waiting for it.
        if self.rate_limited(self.now()) {
            return Ok(());
        }
        let _flight = self.begin_flight(py)?;
        if self.rate_limited(self.now()) {
            return Ok(());
        }
        self.fetch(py).map(|_| ())
    }

    /// `rp.verify_id_token` against this cache's key set for `issuer`; same
    /// keyword options. If the token's `kid` is not in the (non-empty-kid)
    /// set, the set is refreshed once (rate-limited) and a still-unknown
    /// `kid` raises `UnknownKeyError`. Tokens without `kid` follow
    /// `verify_id_token`.
    #[pyo3(signature = (id_token, client_id, expected_nonce, allowed_algorithms, *,
                        trusted_additional_audiences = None, unsafe_skip_nonce_check = false,
                        leeway = None, max_age = None, acr_values = None, access_token = None,
                        require_at_hash = false, authorization_code = None,
                        require_c_hash = false, strict_hashes = false))]
    #[allow(clippy::too_many_arguments)]
    fn verify_id_token<'py>(
        &self,
        py: Python<'py>,
        id_token: &str,
        client_id: &str,
        expected_nonce: Option<&str>,
        allowed_algorithms: Vec<String>,
        trusted_additional_audiences: Option<Vec<String>>,
        unsafe_skip_nonce_check: bool,
        leeway: Option<i64>,
        max_age: Option<i64>,
        acr_values: Option<Vec<String>>,
        access_token: Option<String>,
        require_at_hash: bool,
        authorization_code: Option<String>,
        require_c_hash: bool,
        strict_hashes: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        check_nonce_policy(py, expected_nonce, unsafe_skip_nonce_check)?;
        let policy = IdTokenPolicy::new(
            &allowed_algorithms,
            trusted_additional_audiences,
            leeway,
            max_age,
            acr_values,
            access_token,
            require_at_hash,
            authorization_code,
            require_c_hash,
            strict_hashes,
        )?;
        reject_published_mac(py, &policy.algorithms)?;
        let set = self.resolve_for_token(py, id_token)?;
        Ok(policy
            .verify(py, &set, id_token, &self.issuer, client_id, expected_nonce)?
            .into_bound(py))
    }
}

// ---------------------------------------------------------------------------
// DiscoveryCache
// ---------------------------------------------------------------------------

/// One successful discovery fetch.
struct DiscoveryEntry {
    metadata: ProviderMetadata,
    /// `ProviderInfo.from_metadata(metadata)`, built once per fetch so its
    /// `UserWarning`s fire once per fetch.
    info: ProviderInfo,
    expires_at: f64,
    /// Monotonically increasing, assigned when a fetched entry is installed
    /// (fetches are serialised by the flight). Orders entries for `jwks()`.
    generation: u64,
}

#[derive(Default)]
struct DiscoveryState {
    entry: Option<Arc<DiscoveryEntry>>,
    /// The latest failed fetch (a traceback-free copy of the error and the
    /// clock reading when it finished); cleared by a successful fetch. Drives
    /// `failure_backoff`; see `DiscoveryCache::record_failure`.
    failure: Option<(PyErr, f64)>,
}

/// A copy of `e` without traceback or implicit context, with its `__cause__`
/// chain copied the same way (at most `depth` links, then cut). `copy.copy` of
/// an exception keeps the type, args and instance attributes (`code`,
/// `retryable`, `upstream_*`, ...) and drops `__traceback__`. If copying fails
/// the traceback of `e` itself is cleared instead (it is already the caller's
/// by then; losing it beats pinning frames).
fn detached_copy(py: Python<'_>, e: &PyErr, depth: usize) -> PyErr {
    let value = e.value(py);
    let copied = py
        .import("copy")
        .and_then(|m| m.call_method1("copy", (value,)))
        .ok()
        .and_then(|c| c.cast_into::<pyo3::exceptions::PyBaseException>().ok());
    let Some(copy) = copied else {
        let kept = e.clone_ref(py);
        kept.set_traceback(py, None);
        return kept;
    };
    let _ = copy.setattr("__traceback__", py.None());
    let cause = value
        .getattr("__cause__")
        .ok()
        .filter(|c| !c.is_none() && depth > 0)
        .map(|c| detached_copy(py, &PyErr::from_value(c), depth - 1));
    let out = PyErr::from_value(copy.into_any());
    out.set_cause(py, cause);
    out
}

/// What `DiscoveryCache::backoff_outcome` decided for a call inside the
/// back-off window of a failed fetch.
enum Backoff {
    Stale(Arc<DiscoveryEntry>),
    Refused(PyErr),
}

/// A caching OpenID Provider discovery client for one issuer.
///
/// `metadata()` returns the provider's discovery document and `info()` the
/// matching `ProviderInfo` (built once per fetch, so the `UserWarning`s of
/// `ProviderInfo.from_metadata` fire once per fetch); `jwks()` returns a
/// `JwksCache` bound to the advertised `jwks_uri` and issuer. The document is
/// refetched when it expires. The lifetime is the response's
/// `Cache-Control: max-age` minus `Age` when present, else `default_ttl`,
/// clamped to `[min_ttl, max_ttl]` (so `no-store` / `no-cache` / `max-age=0`
/// are floored to `min_ttl`). Cache-Control is honoured only when the
/// `HttpClient` reports response headers (the built-in client does; a Python
/// adapter must return them, see `HttpFetchResponse`); otherwise `default_ttl`
/// applies and a `UserWarning` is emitted on the first fetch. The discovery
/// issuer check of `rp.discover` applies on every fetch: a document whose
/// `issuer` differs from the configured one raises and is neither cached nor
/// served.
///
/// Concurrent callers share a single fetch. `fetch_timeout` (seconds, at least
/// 1e-9, default 45) bounds how long a thread WAITS for another thread's
/// in-flight fetch; on expiry the waiter raises
/// `InternalError(code="discovery_fetch_timeout")`. The fetch carries on and
/// its result is cached when it finishes; before raising, the waiter applies
/// the stale policy below and is served the previous document if allowed. The
/// `JwksCache` built by `jwks()` uses the same `fetch_timeout`, `http` client
/// and clock, and the `JwksCache` constructor defaults for its TTL parameters.
///
/// After a failed fetch no new network call is made for `failure_backoff`
/// seconds. In that window, and also when a fetch of an expired entry fails,
/// the previous document is served ONLY if `stale_on_error` is true and the
/// entry expired less than `max_stale` seconds ago (a one-time `UserWarning`
/// is emitted when stale metadata is first served after a failure). Otherwise
/// the original error is raised, or inside the window
/// `InternalError(code="discovery_backoff")` chained to a traceback-free copy
/// of it (`__cause__`); its `retryable` is the cause's.
/// This differs from `JwksCache`, which never serves an expired key set:
/// metadata changes rarely and an outage of the well-known endpoint should
/// not break login, while keys stay never-stale through the `JwksCache` that
/// `jwks()` returns.
///
/// The cache is plain in-process memory: it stays valid in a forked child, but
/// fork only while no other thread is inside a cache call.
///
/// `_now` is a private test hook: a zero-argument callable returning the
/// clock in seconds.
#[pyclass(module = "pygrindvakt.rp", name = "DiscoveryCache", frozen)]
pub struct DiscoveryCache {
    http: Option<Py<PyAny>>,
    issuer: String,
    default_ttl: u64,
    min_ttl: u64,
    max_ttl: u64,
    failure_backoff: u64,
    stale_on_error: bool,
    max_stale: u64,
    fetch_timeout: std::time::Duration,
    allow_cross_origin_end_session: bool,
    clock: Option<Py<PyAny>>,
    state: RwLock<DiscoveryState>,
    /// The `JwksCache` handed out by `jwks()` and the generation of the
    /// metadata entry it was built for.
    jwks_slot: Mutex<Option<(u64, Py<JwksCache>)>>,
    /// Source of `DiscoveryEntry::generation`.
    generation: std::sync::atomic::AtomicU64,
    flight: Mutex<bool>,
    flight_done: Condvar,
    /// The no-response-headers warning is emitted once per cache.
    warned_no_headers: std::sync::atomic::AtomicBool,
    /// The stale-served warning is emitted once per outage (re-armed by a
    /// successful fetch).
    warned_stale: std::sync::atomic::AtomicBool,
}

impl DiscoveryCache {
    fn now(&self) -> f64 {
        clock_now(&self.clock)
    }

    fn snapshot(&self) -> Option<Arc<DiscoveryEntry>> {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .entry
            .clone()
    }

    fn valid_entry(&self, now: f64) -> Option<Arc<DiscoveryEntry>> {
        self.snapshot().filter(|e| now < e.expires_at)
    }

    /// An expired entry may be served: opted in and not expired for longer
    /// than `max_stale`.
    fn stale_entry(&self, now: f64) -> Option<Arc<DiscoveryEntry>> {
        if !self.stale_on_error {
            return None;
        }
        self.snapshot()
            .filter(|e| now < e.expires_at + self.max_stale as f64)
    }

    fn begin_flight(&self, py: Python<'_>) -> PyResult<Flight<'_>> {
        begin_flight(
            py,
            &self.flight,
            &self.flight_done,
            self.fetch_timeout,
            "discovery fetch",
            "discovery_fetch_timeout",
        )
    }

    /// Seconds left of the back-off window of the latest failed fetch, if any.
    fn backoff_remaining(&self, now: f64) -> Option<f64> {
        let st = self.state.read().unwrap_or_else(|e| e.into_inner());
        let (_, failed_at) = st.failure.as_ref()?;
        let left = self.failure_backoff as f64 - (now - failed_at);
        (left > 0.0).then_some(left)
    }

    fn warn_stale(&self, py: Python<'_>) {
        if !self
            .warned_stale
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            warn(
                py,
                "serving stale discovery metadata after a failed or timed-out fetch \
                 (stale_on_error=True, bounded by max_stale); a failure is the __cause__ of \
                 discovery_backoff errors and the document is refetched once the provider \
                 recovers",
            );
        }
    }

    /// Inside the back-off window of a failed fetch: serve the stale entry or
    /// refuse with `discovery_backoff` chained to the stored error. `None`
    /// when no window is open.
    fn backoff_outcome(&self, py: Python<'_>, now: f64) -> Option<Backoff> {
        let left = self.backoff_remaining(now)?;
        if let Some(stale) = self.stale_entry(now) {
            self.warn_stale(py);
            return Some(Backoff::Stale(stale));
        }
        let cause = self
            .state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .failure
            .as_ref()
            .map(|(e, _)| e.clone_ref(py));
        // `retryable` follows the stored cause (itself derived by
        // `is_retryable`); no cause readable means not retryable.
        let retryable = cause.as_ref().is_some_and(|c| {
            c.value(py)
                .getattr("retryable")
                .and_then(|v| v.extract::<bool>())
                .unwrap_or(false)
        });
        let msg = format!(
            "the last discovery fetch failed; not retrying for another {:.0}s \
             (failure_backoff={}s, no usable cached metadata)",
            left.ceil(),
            self.failure_backoff
        );
        let e = with_code_retryable(
            py,
            InternalError::new_err(msg),
            "discovery_backoff",
            retryable,
        );
        e.set_cause(py, cause);
        Some(Backoff::Refused(e))
    }

    /// Record a failed fetch for the back-off window. A traceback-free copy is
    /// stored (the original, with its frames, locals and HTTP requests, goes
    /// to the caller only), so the failure does not pin that memory for the
    /// window and `discovery_backoff` errors chained to it add nothing to it.
    /// Returns the clock reading of the failure.
    fn record_failure(&self, py: Python<'_>, e: &PyErr) -> f64 {
        let now = self.now();
        let stored = detached_copy(py, e, 4);
        let old = self
            .state
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .failure
            .replace((stored, now));
        // Dropping a PyErr may run Python code: not under the lock.
        drop(old);
        now
    }

    /// Record a failed fetch; serve stale metadata if allowed, else give the
    /// error back.
    fn on_failure(&self, py: Python<'_>, e: PyErr) -> PyResult<Arc<DiscoveryEntry>> {
        let now = self.record_failure(py, &e);
        match self.stale_entry(now) {
            Some(stale) => {
                self.warn_stale(py);
                Ok(stale)
            }
            None => Err(e),
        }
    }

    /// Fetch, validate and store the document. The caller holds the flight.
    fn fetch(&self, py: Python<'_>) -> PyResult<Arc<DiscoveryEntry>> {
        // A fresh client (and `Failures` slot) per fetch, so a transport
        // error is chained to this call's failure only.
        let (http, failures) = extract_http_client(self.http.as_ref().map(|h| h.bind(py)))?;
        let d = discover_recorded(py, http, &failures, self.issuer.clone())?;
        if d.headerless
            && !self
                .warned_no_headers
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            warn(
                py,
                &format!(
                    "this HttpClient reports no response headers; Cache-Control is ignored and \
                     default_ttl ({}s) applies to discovery; return headers from your HttpClient \
                     or lower default_ttl/max_ttl",
                    self.default_ttl
                ),
            );
        }
        // `Cache-Control` / `Age` are parsed by the upstream quote-aware
        // parser: remaining freshness, capped at `max_ttl`.
        let ttl = d
            .response
            .cache_ttl_secs_max(self.max_ttl)
            .unwrap_or(self.default_ttl)
            .clamp(self.min_ttl, self.max_ttl);
        let info =
            ProviderInfo::from_metadata(py, &d.metadata, self.allow_cross_origin_end_session)?;
        let entry = Arc::new(DiscoveryEntry {
            metadata: d.metadata,
            info,
            expires_at: self.now() + ttl as f64,
            generation: self
                .generation
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1,
        });
        let old = {
            let mut st = self.state.write().unwrap_or_else(|e| e.into_inner());
            let failure = st.failure.take();
            st.entry = Some(entry.clone());
            failure
        };
        drop(old);
        self.warned_stale
            .store(false, std::sync::atomic::Ordering::Relaxed);
        Ok(entry)
    }

    /// The current entry, fetching first if there is none or it expired.
    fn current(&self, py: Python<'_>) -> PyResult<Arc<DiscoveryEntry>> {
        let now = self.now();
        if let Some(e) = self.valid_entry(now) {
            return Ok(e);
        }
        match self.backoff_outcome(py, now) {
            Some(Backoff::Stale(e)) => return Ok(e),
            Some(Backoff::Refused(e)) => return Err(e),
            None => {}
        }
        let _flight = match self.begin_flight(py) {
            Ok(f) => f,
            Err(timeout) => {
                // Timed out waiting for the fetching thread: the stale policy
                // applies as it does to a failed fetch. The timeout is not
                // recorded as a failure (the fetch is still running).
                let now = self.now();
                if let Some(e) = self.valid_entry(now) {
                    return Ok(e);
                }
                return match self.stale_entry(now) {
                    Some(stale) => {
                        self.warn_stale(py);
                        Ok(stale)
                    }
                    None => Err(timeout),
                };
            }
        };
        // Another thread may have fetched (or failed) while we waited.
        let now = self.now();
        if let Some(e) = self.valid_entry(now) {
            return Ok(e);
        }
        match self.backoff_outcome(py, now) {
            Some(Backoff::Stale(e)) => return Ok(e),
            Some(Backoff::Refused(e)) => return Err(e),
            None => {}
        }
        match self.fetch(py) {
            Ok(e) => Ok(e),
            Err(e) => self.on_failure(py, e),
        }
    }
}

#[pymethods]
impl DiscoveryCache {
    #[new]
    #[pyo3(signature = (http, issuer, *, default_ttl = 3600, min_ttl = 60, max_ttl = 86400,
                        failure_backoff = 10, stale_on_error = true, max_stale = 86400,
                        fetch_timeout = 45.0, allow_cross_origin_end_session = false,
                        _now = None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        http: Option<&Bound<'_, PyAny>>,
        issuer: String,
        default_ttl: i64,
        min_ttl: i64,
        max_ttl: i64,
        failure_backoff: i64,
        stale_on_error: bool,
        max_stale: i64,
        fetch_timeout: f64,
        allow_cross_origin_end_session: bool,
        _now: Option<Py<PyAny>>,
    ) -> PyResult<Self> {
        // Validate the client and the issuer now rather than on first use.
        extract_http_client(http)?;
        reject_reinterpreted_url_chars("issuer", &issuer).map_err(config_from)?;
        grp::validate_issuer(&issuer).map_err(config_from)?;
        let get = |n: &str, v: i64| seconds(n, Some(v)).map(Option::unwrap_or_default);
        let (default_ttl, min_ttl, max_ttl) = (
            get("default_ttl", default_ttl)?,
            get("min_ttl", min_ttl)?,
            get("max_ttl", max_ttl)?,
        );
        if min_ttl > max_ttl {
            return Err(config_err("min_ttl must not exceed max_ttl"));
        }
        let failure_backoff = get("failure_backoff", failure_backoff)?;
        let max_stale = get("max_stale", max_stale)?;
        let fetch_timeout = parse_fetch_timeout(fetch_timeout)?;
        Ok(Self {
            http: http.filter(|h| !h.is_none()).map(|h| h.clone().unbind()),
            issuer,
            default_ttl,
            min_ttl,
            max_ttl,
            failure_backoff,
            stale_on_error,
            max_stale,
            fetch_timeout,
            allow_cross_origin_end_session,
            clock: _now,
            state: RwLock::default(),
            jwks_slot: Mutex::new(None),
            generation: Default::default(),
            flight: Mutex::new(false),
            flight_done: Condvar::new(),
            warned_no_headers: Default::default(),
            warned_stale: Default::default(),
        })
    }

    /// The issuer this cache discovers.
    #[getter]
    fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Seconds after a failed fetch during which no new fetch is attempted.
    #[getter]
    fn failure_backoff(&self) -> u64 {
        self.failure_backoff
    }

    /// Seconds a thread waits for another thread's in-flight fetch.
    #[getter]
    fn fetch_timeout(&self) -> f64 {
        self.fetch_timeout.as_secs_f64()
    }

    fn __repr__(&self) -> String {
        let (jwks_uri, expires_in) = match self.snapshot() {
            Some(e) => {
                let left = (e.expires_at - self.now()).max(0.0) as u64;
                (e.info.inner.jwks_uri.clone(), Some(left))
            }
            None => (None, None),
        };
        let quoted = |s: &str| format!("'{}'", escape_untrusted_quoted(s, 256));
        format!(
            "DiscoveryCache(issuer={}, jwks_uri={}, expires_in={})",
            quoted(&self.issuer),
            jwks_uri.as_deref().map_or("None".to_string(), quoted),
            expires_in.map_or("None".to_string(), |n| n.to_string()),
        )
    }

    /// The provider's discovery document (a `ProviderMetadata`), fetching it
    /// first if none is cached or it expired. See the class documentation for
    /// the failure, back-off and stale policy.
    fn metadata(&self, py: Python<'_>) -> PyResult<ProviderMetadata> {
        Ok(self.current(py)?.metadata.clone())
    }

    /// `ProviderInfo.from_metadata(metadata())`, built once per fetch.
    fn info(&self, py: Python<'_>) -> PyResult<ProviderInfo> {
        Ok(self.current(py)?.info.clone())
    }

    /// A `JwksCache` bound to the advertised `jwks_uri` and issuer. The SAME
    /// object is returned across metadata refreshes (so its cached keys
    /// survive); it is replaced only when the new document advertises a
    /// different `jwks_uri` or issuer, and the old object is then never
    /// returned again. Do not keep the object across calls if the provider may
    /// move its keys: call `jwks()` each time. Raises `ConfigError` when the
    /// provider advertises no `jwks_uri`.
    fn jwks(&self, py: Python<'_>) -> PyResult<Py<JwksCache>> {
        let entry = self.current(py)?;
        let Some(uri) = entry.info.inner.jwks_uri.clone() else {
            return Err(config_err(
                "the provider's discovery document advertises no jwks_uri",
            ));
        };
        let issuer = entry.info.inner.issuer.clone();
        let generation = entry.generation;
        // What the slot says for a caller holding the entry of `generation`:
        // reuse a matching cache (bumping the slot generation so an older
        // entry can never replace it), serve the cache of a NEWER entry (the
        // caller's entry is stale), or nothing: build and install.
        let decide = |slot: &mut Option<(u64, Py<JwksCache>)>| {
            let (slot_gen, cache) = slot.as_mut()?;
            let c = cache.get();
            if c.jwks_uri == uri && c.issuer == issuer {
                *slot_gen = (*slot_gen).max(generation);
                Some(cache.clone_ref(py))
            } else if *slot_gen > generation {
                Some(cache.clone_ref(py))
            } else {
                None
            }
        };
        // The lock is never held across anything that can run Python code
        // (which might release the GIL): a thread holding it while another
        // thread waits for it with the GIL would deadlock.
        if let Some(c) = decide(&mut self.jwks_slot.lock().unwrap_or_else(|e| e.into_inner())) {
            return Ok(c);
        }
        let http = self.http.as_ref().map(|h| h.bind(py).clone());
        let built = Py::new(
            py,
            JwksCache::build(
                http.as_ref(),
                uri.clone(),
                issuer.clone(),
                JWKS_DEFAULT_TTL,
                JWKS_MIN_TTL,
                JWKS_MAX_TTL,
                JWKS_MIN_REFRESH_INTERVAL,
                self.fetch_timeout.as_secs_f64(),
                self.clock.as_ref().map(|c| c.clone_ref(py)),
            )?,
        )?;
        let (result, old) = {
            let mut slot = self.jwks_slot.lock().unwrap_or_else(|e| e.into_inner());
            match decide(&mut slot) {
                // Another thread installed a matching or newer one meanwhile.
                Some(c) => (c, None),
                None => (
                    built.clone_ref(py),
                    slot.replace((generation, built)).map(|(_, c)| c),
                ),
            }
        };
        drop(old);
        Ok(result)
    }

    /// Force a refetch. A call within `failure_backoff` seconds of a failed
    /// fetch is a silent no-op. A failed fetch raises the original error and
    /// keeps the cached document (it is not served from here; `metadata()`
    /// applies the stale policy).
    fn refresh(&self, py: Python<'_>) -> PyResult<()> {
        if self.backoff_remaining(self.now()).is_some() {
            return Ok(());
        }
        let _flight = self.begin_flight(py)?;
        // Another thread's fetch may have failed while we waited.
        if self.backoff_remaining(self.now()).is_some() {
            return Ok(());
        }
        match self.fetch(py) {
            Ok(_) => Ok(()),
            Err(e) => {
                self.record_failure(py, &e);
                Err(e)
            }
        }
    }
}

/// Fetch the UserInfo document with a Bearer `access_token` and return its
/// claims as a dict, bound to `expected_sub` (the validated id_token subject).
///
/// `userinfo_endpoint` may be `None` (the OP did not advertise one), which
/// raises `ConfigError`. `method` is `"POST"` (default; empty form body) or
/// `"GET"` (needs an `http` client that supports request headers on GET, see
/// `pygrindvakt.http`).
///
/// A JSON response is parsed directly. A signed (`application/jwt`) response
/// fails closed unless `jwks`, `client_id`, `allowed_algorithms` and `trust`
/// are all given (`AuthnError`, `code == "userinfo_unverifiable"`). `trust`
/// states how the JWT is proven to be UserInfo and not a replayed id_token:
/// `"typed"` (needs `typ`), `"dedicated_keys"` or
/// `"untyped_shared_key_compat"` (weakest). `max_age` bounds the token age
/// from `iat` (default 300 s); `None` removes the bound, leaving replay
/// unbounded. Encrypted (JWE) responses are not supported.
///
/// `allowed_algorithms` containing `HS*` works with a caller-built `jwks`
/// (an `oct` key from the `client_secret`, at least 32 / 48 / 64 bytes, else
/// `ConfigError(code="weak_shared_secret")`); with a `JwksCache` it raises
/// `ConfigError(code="shared_secret_algorithm")`.
#[pyfunction]
#[pyo3(signature = (http, userinfo_endpoint, access_token, expected_sub, issuer, *,
                    method = "POST", jwks = None, client_id = None,
                    allowed_algorithms = None, trust = None, typ = None,
                    max_age = Some(grp::DEFAULT_USERINFO_JWT_MAX_AGE), require_exp = false))]
#[allow(clippy::too_many_arguments)]
fn fetch_userinfo<'py>(
    py: Python<'py>,
    http: Option<&Bound<'py, PyAny>>,
    userinfo_endpoint: Option<String>,
    access_token: String,
    expected_sub: String,
    issuer: String,
    method: &str,
    jwks: Option<&Bound<'py, PyAny>>,
    client_id: Option<String>,
    allowed_algorithms: Option<Vec<String>>,
    trust: Option<&str>,
    typ: Option<String>,
    max_age: Option<u64>,
    require_exp: bool,
) -> PyResult<Bound<'py, PyAny>> {
    let method = match method {
        "POST" => grp::UserinfoMethod::Post,
        "GET" => grp::UserinfoMethod::Get,
        other => {
            return Err(config_err(format!(
                "method must be \"POST\" or \"GET\", got {other:?}"
            )))
        }
    };
    if let Some(other) =
        trust.filter(|t| !matches!(*t, "typed" | "dedicated_keys" | "untyped_shared_key_compat"))
    {
        return Err(config_err(format!(
            "trust must be \"typed\", \"dedicated_keys\" or \"untyped_shared_key_compat\", \
             got {other:?}"
        )));
    }
    if trust == Some("typed") && typ.is_none() {
        return Err(config_err("trust=\"typed\" requires typ"));
    }
    if typ.is_some() && trust != Some("typed") {
        return Err(config_err("typ is only used with trust=\"typed\""));
    }
    let jwks = jwks.map(JwksSource::from_py).transpose()?;
    if let Some(jwks) = &jwks {
        jwks.check_issuer(&issuer)?;
    }
    let algs = allowed_algorithms
        .map(|algs| parse_algorithms(&algs))
        .transpose()?;
    if let (Some(jwks), Some(algs)) = (&jwks, &algs) {
        jwks.check_algorithms(py, algs)?;
    }
    let Some(userinfo_endpoint) = userinfo_endpoint else {
        return Err(config_err(
            "provider does not advertise a userinfo_endpoint",
        ));
    };

    let (http, failures) = extract_http_client(http)?;
    let resp = crate::runtime::block_on(py, async move {
        grp::fetch_userinfo_response(&http, &userinfo_endpoint, &access_token, &issuer, method)
            .await
            .map(|resp| (resp, issuer))
    })?;
    let (resp, issuer) = resp.map_err(|e| failures.err(py, e))?;

    let content_type = resp
        .content_type
        .as_deref()
        .or(resp.header("content-type"))
        .unwrap_or("");
    let is_jwt = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("application/jwt");
    let claims = if !is_jwt {
        grp::userinfo_json_claims(&resp, &expected_sub).map_err(err)?
    } else {
        // Five dot-separated segments is a compact JWE.
        if resp.text().trim().split('.').count() == 5 {
            return Err(with_code(
                py,
                AuthnError::new_err(
                    "userinfo is an encrypted JWT (JWE); encrypted UserInfo responses are not supported",
                ),
                "userinfo_encrypted",
            ));
        }
        let unverifiable = |what: &str| {
            with_code(
                py,
                AuthnError::new_err(format!(
                    "userinfo is a signed JWT but cannot be verified: {what} required \
                     (refusing to trust an unverified response)"
                )),
                "userinfo_unverifiable",
            )
        };
        let jwks = jwks.as_ref().ok_or_else(|| unverifiable("jwks"))?;
        let client_id = client_id.ok_or_else(|| unverifiable("client_id"))?;
        let algs = algs
            .filter(|a| !a.is_empty())
            .ok_or_else(|| unverifiable("allowed_algorithms"))?;
        let mut options = match trust {
            Some("typed") => grp::UserinfoJwtOptions::typed(typ.as_deref().unwrap_or_default()),
            Some("dedicated_keys") => grp::UserinfoJwtOptions::dedicated_keys(),
            Some(_) => grp::UserinfoJwtOptions::untyped_shared_key_compat(),
            None => return Err(unverifiable("trust")),
        };
        options = match max_age {
            Some(secs) => options.with_max_age(secs),
            None => options.without_max_age(),
        };
        if require_exp {
            options = options.with_require_exp();
        }
        // A cache refreshes once if the response's `kid` is unknown.
        let jwks = jwks.resolve(py, resp.text().trim(), &issuer)?;
        let jwks = prepare_mac_keys(py, &jwks, resp.text().trim(), &algs, KeySelection::Named)?;
        grp::userinfo_signed_claims(
            &jwks,
            &resp,
            &issuer,
            &client_id,
            &expected_sub,
            &algs,
            &options,
        )
        .map_err(err)?
    };
    to_py(py, &claims)
}

/// Build a `private_key_jwt` client assertion (RFC 7523) signed with `key`:
/// `iss` = `sub` = `client_id`, `aud` = `audience` (the token endpoint URL),
/// valid for 300 seconds, with a random `jti`.
#[pyfunction]
fn build_client_assertion(key: &SigningKey, client_id: &str, audience: &str) -> PyResult<String> {
    grp::build_client_assertion(&key.inner, client_id, audience).map_err(err)
}

/// Convert a userinfo / id_token claims dict into the proxy's attribute map
/// shape, `{name: [values]}`: strings become one-element lists, lists keep
/// their string members, numbers and booleans are stringified, and anything
/// else (nested objects, null, empty lists) is dropped.
#[pyfunction]
fn claims_to_attributes(claims: &Bound<'_, PyAny>) -> PyResult<BTreeMap<String, Vec<String>>> {
    let v: serde_json::Value = from_py(claims)?;
    Ok(grp::claims_to_attributes(&v))
}

/// Largest `leeway` (seconds) `verify_id_token` accepts; a larger value raises
/// `ConfigError`. A cap on skew tolerance, not a recommended value.
const MAX_ID_TOKEN_LEEWAY: u64 = grp::MAX_ID_TOKEN_LEEWAY;

/// Check the syntax of an issuer identifier.
///
/// Requires an absolute `https` URL (`http` only for loopback hosts) with no
/// userinfo, query, fragment, whitespace, control or invisible characters.
/// Raises `ConfigError` (a `ValueError`, `status_hint` 500) otherwise: the
/// issuer is integrator configuration or provider metadata, not request
/// input. It checks syntax only: it does NOT establish that the issuer is
/// trusted, nor that it matches any discovery metadata. Backslashes are
/// rejected: the URL parser would reinterpret them as `/`, so the parsed
/// authority would differ from the raw string. Compare issuers byte-for-byte
/// (exact string match); never suffix/substring checks.
#[pyfunction]
fn validate_issuer(issuer: &str) -> PyResult<()> {
    reject_reinterpreted_url_chars("issuer", issuer).map_err(config_from)?;
    grp::validate_issuer(issuer).map_err(config_from)
}

/// Check the syntax of a redirect URI.
///
/// Requires an absolute URL without a fragment (upstream's rule) and, as
/// binding-side hardening stricter than core 0.9, rejects whitespace,
/// control, bidi and invisible formatting characters and userinfo
/// (`https://good.example@evil.example/cb`). Raises `BadRequestError`
/// otherwise (not `ConfigError`: a redirect URI can come from a request).
/// This checks syntax only. The scheme is NOT checked, so custom/native-app
/// schemes such as `com.example.app:/cb` pass, and so do `javascript:`,
/// `file:` and `http://attacker.example/cb`.
///
/// It is the syntax step of `RpClient`'s redirect URI handling, which also
/// requires registration, exact-string comparison and a transport check
/// (ADR 0004). It is NOT a registration policy and does NOT make a URI safe
/// to register or redirect to. Do not use it to vet client registrations on
/// an OP: this library provides no OP-side registration policy, so apply an
/// https or scheme allow-list and compare by EXACT match yourself.
///
/// Backslashes are rejected: the URL parser would reinterpret them as `/`,
/// making the parsed authority differ from the raw string.
#[pyfunction]
fn validate_redirect_uri_syntax(redirect_uri: &str) -> PyResult<()> {
    check_redirect_uri(redirect_uri).map_err(err)
}

/// The loopback `http` development exception is opt-in: pass
/// `allow_loopback_http=True` AND `issuer`, which must be the authenticated,
/// locally configured issuer, never a value taken from the document being
/// validated. A loopback `http` issuer then permits loopback `http` endpoints
/// on ANY port.
///
/// Checks that a metadata endpoint is an absolute `https` URL. `name` appears
/// in the error message. By default (`allow_loopback_http=False`) only `https`
/// passes; if `issuer` is given it is still validated first (as
/// `validate_issuer`, so an invalid issuer fails closed) but never enables
/// loopback `http`. With `allow_loopback_http=True`, `issuer` is required
/// (`ConfigError` otherwise), and loopback `http` is also allowed when the
/// issuer is itself a loopback `http` origin; a `UserWarning` is emitted
/// whenever a plain `http` endpoint is accepted that way. Raises
/// `ConfigError` (a `ValueError`, `status_hint` 500) otherwise: endpoints come
/// from integrator configuration or provider metadata, not request input. It
/// does NOT check same-origin with the issuer (it never compares hosts) or
/// establish trust. Backslashes in `endpoint` or `issuer` are rejected: the
/// URL parser would reinterpret them as `/`, making the parsed authority
/// differ from the raw string. Compare issuers byte-for-byte (exact string
/// match); never suffix/substring checks.
#[pyfunction]
#[pyo3(signature = (name, endpoint, issuer = None, *, allow_loopback_http = false))]
fn validate_service_endpoint(
    py: Python<'_>,
    name: &str,
    endpoint: &str,
    issuer: Option<&str>,
    allow_loopback_http: bool,
) -> PyResult<()> {
    reject_reinterpreted_url_chars(name, endpoint).map_err(config_from)?;
    if let Some(issuer) = issuer {
        reject_reinterpreted_url_chars("issuer", issuer).map_err(config_from)?;
        grp::validate_issuer(issuer).map_err(config_from)?;
    }
    if !allow_loopback_http {
        return grp::validate_service_endpoint(name, endpoint).map_err(config_from);
    }
    let Some(issuer) = issuer else {
        return Err(config_err(
            "validate_service_endpoint: allow_loopback_http=True requires issuer",
        ));
    };
    grp::validate_service_endpoint_for_issuer(name, endpoint, issuer).map_err(config_from)?;
    let is_http = endpoint
        .get(..5)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http:"));
    if is_http {
        warn(
            py,
            &format!(
                "validate_service_endpoint: plain http {name} accepted only because \
                 allow_loopback_http=True was requested explicitly and the issuer is a \
                 loopback http origin; this is a development-only exception that allows \
                 loopback endpoints on any port. The issuer must be the one you configured \
                 and authenticated, never the `issuer` field of an unauthenticated document"
            ),
        );
    }
    Ok(())
}

/// The classical asymmetric JWS algorithm names from core's catalogue
/// (`grindvakt::JWS_ALGORITHMS`): `RS256/384/512`, `PS256/384/512`,
/// `ES256/384/512`, `EdDSA` and `ES256K`, in core's order. `HS*` and `none`
/// are never included. Only these names are ever listed, so a name core adds
/// later (post-quantum ML-DSA, feature-gated in jose-rs) is NOT included until
/// the binding adds it.
///
/// It is a catalogue, not a recommended allowlist, not a list an OP
/// advertises, and not what is appropriate for your deployment; pass an
/// explicit allowlist to `verify_id_token`. It includes `EdDSA`, for which
/// `jwt.supports_oidc_token_hash` is False, so
/// `allowed_algorithms=rp.asymmetric_algorithms()` with `strict_hashes=True`
/// on a flow that needs `at_hash` / `c_hash` is unsatisfiable for EdDSA
/// tokens: filter with `jwt.supports_oidc_token_hash` or pass an explicit
/// allowlist.
#[pyfunction]
fn asymmetric_algorithms() -> Vec<&'static str> {
    // Fixed names (RFC 7518 / RFC 8037 / RFC 8812), intersected with core's
    // catalogue: a name core drops disappears, but one core adds is never
    // listed without a decision here (a MAC-style addition cannot leak in).
    const KNOWN_ASYMMETRIC: [&str; 11] = [
        "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "ES256K",
        "EdDSA",
    ];
    grindvakt::JWS_ALGORITHMS
        .iter()
        .copied()
        .filter(|a| !grindvakt::is_symmetric_jws_algorithm(a))
        .map(JwsAlgorithm::as_str)
        .filter(|n| KNOWN_ASYMMETRIC.contains(n))
        .collect()
}

// ---------------------------------------------------------------------------
// Authorization response (callback) parsing
// ---------------------------------------------------------------------------

/// Parameters this parser owns; each may appear at most once, and none may
/// ride in the query string of a `form_post` callback.
const RESPONSE_PARAMS: [&str; 7] = [
    "code",
    "state",
    "error",
    "error_description",
    "error_uri",
    "iss",
    "response",
];

/// Cap (characters) of `AuthorizationResponse.error_description_safe`.
const ERROR_DESCRIPTION_SAFE_MAX: usize = 256;

fn bad_response(msg: impl Into<String>) -> PyErr {
    err(RsError::BadRequest(msg.into()))
}

/// The callback of an authorization request, parsed and shape-checked.
///
/// Built by `parse_authorization_response`; there is no public constructor.
/// Nothing in it is trusted: the response proves nothing until the caller has
/// checked `state` with `matches_state` (constant time), compared `iss`
/// with `matches_iss` (RFC 9207) and exchanged the code. The raw
/// `error_description` is not available by design (it is provider-controlled
/// text); only `error_description_safe` is. `error_uri` is exposed only when
/// it is a safe absolute https URL (http only for loopback) and must never be followed or rendered as
/// a link without your own validation. `repr()` never prints `code` or
/// `state`.
#[pyclass(
    module = "pygrindvakt.rp",
    name = "AuthorizationResponse",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct AuthorizationResponse {
    inner: gcb::AuthorizationResponse,
    /// Transport label (`query` / `fragment` / `form_post`); the core's own
    /// mode is `Jwt` for a JARM stub, which the binding never reports.
    transport: &'static str,
    /// Escaped with the binding's escaper from the single raw value.
    error_description_safe: Option<String>,
    /// Core's normalised `error_uri` minus any URL with a fragment.
    error_uri: Option<String>,
}

#[pymethods]
impl AuthorizationResponse {
    /// The authorization code, verbatim, or `None` for an error response.
    #[getter]
    fn code(&self) -> Option<&str> {
        self.inner.code()
    }
    /// The `state` echoed by the OP, verbatim. Check it with `matches_state`
    /// (constant time) before anything else.
    #[getter]
    fn state(&self) -> Option<&str> {
        self.inner.state()
    }
    /// The OAuth error code (RFC 6749 charset, at most 64 characters), or
    /// `None`. Unknown codes are kept; see `error_known`.
    #[getter]
    fn error(&self) -> Option<&str> {
        self.inner.error()
    }
    /// `error_description` escaped (control, bidi and invisible characters)
    /// and capped at 256 characters. The raw value is not exposed.
    #[getter]
    fn error_description_safe(&self) -> Option<&str> {
        self.error_description_safe.as_deref()
    }
    /// `error_uri` if it is an absolute https URL (plain http only for
    /// loopback hosts) with a host and no whitespace, control characters,
    /// backslash or userinfo, at most 2048 characters; returned in its normalised form (what was validated).
    /// Otherwise `None`. Untrusted.
    #[getter]
    fn error_uri(&self) -> Option<&str> {
        self.error_uri.as_deref()
    }
    /// The RFC 9207 `iss` parameter, verbatim, or `None`. Compare it with
    /// `matches_iss`.
    #[getter]
    fn iss(&self) -> Option<&str> {
        self.inner.iss()
    }
    /// The raw JARM `response` JWT, at most 32768 characters. Untrusted
    /// unless `jarm_verified`. Only set when `accept_jarm=True` was passed.
    #[getter]
    fn response(&self) -> Option<&str> {
        self.inner.jarm_response()
    }
    /// How the response arrived: `"query"`, `"fragment"` or `"form_post"`.
    #[getter]
    fn response_mode(&self) -> &str {
        self.transport
    }
    /// True when the response carries an OAuth `error`.
    #[getter]
    fn is_error(&self) -> bool {
        self.inner.is_error()
    }
    /// True when `error` is a code the binding knows (RFC 6749, OIDC Core,
    /// DPoP). Unknown codes are kept, never rejected. "Known" is WIDER than
    /// what `OAuthError` accepts (8 response-only codes such as
    /// `consent_required` are known but `OAuthError(...)` raises
    /// `ValueError` for them): never construct `OAuthError(resp.error)` from a
    /// callback value without catching `ValueError`; branch on the `error`
    /// string instead.
    #[getter]
    fn error_known(&self) -> bool {
        self.inner.error_known()
    }

    /// RFC 9207 issuer check, fail closed: exact, byte-for-byte comparison of
    /// `iss` with `expected`. When the response has no `iss` the result is
    /// `not required`, so False by default. Pass `required=False` ONLY when
    /// the OP does not advertise `authorization_response_iss_parameter_supported`
    /// (RFC 9207 section 2.4). An empty `expected` is a configuration fault
    /// and always returns False, regardless of `required`, as does an
    /// unverified JARM stub (`response` set; the binding cannot verify it).
    /// Never raises. The caller MUST call it; parsing does not.
    #[pyo3(signature = (expected, *, required = true))]
    fn matches_iss(&self, expected: &str, required: bool) -> bool {
        self.inner.matches_iss(expected, required)
    }

    /// `state` check, fail closed: constant-time comparison of the UTF-8
    /// bytes of the response `state` with `expected` (the value stored in the
    /// session; RFC 6749 sections 4.1.2.3 and 10.12). When the response has
    /// no `state` the result is `not required`, so False by default.
    /// `rp.authorization_url` and `rp.begin` always send `state`, so keep
    /// `required=True`; pass `required=False` only for a request deliberately
    /// built without `state`. Never raises for a mismatch. The caller MUST
    /// call it before exchanging the code; parsing does not. An empty
    /// `expected` (no state stored in the session) always returns False,
    /// regardless of `required`, as does an unverified JARM stub (`response`
    /// set).
    #[pyo3(signature = (expected, *, required = true))]
    fn matches_state(&self, expected: &str, required: bool) -> bool {
        self.inner.matches_state(expected, required)
    }

    /// True only for the result of a successful `verify_jarm`.
    #[getter]
    fn jarm_verified(&self) -> bool {
        self.inner.jarm_verified()
    }

    /// Verify the JARM `response` JWT of this stub (see the `.pyi` stub for
    /// the full contract) and return the inner response. Fails closed.
    #[pyo3(signature = (jwks, *, issuer, client_id, allowed_algorithms, trust = "typed",
                        typ = None, leeway = None))]
    #[allow(clippy::too_many_arguments)]
    fn verify_jarm<'py>(
        &self,
        py: Python<'py>,
        jwks: &Bound<'py, PyAny>,
        issuer: &str,
        client_id: &str,
        allowed_algorithms: Vec<String>,
        trust: &str,
        typ: Option<&str>,
        leeway: Option<i64>,
    ) -> PyResult<AuthorizationResponse> {
        if !matches!(
            trust,
            "typed" | "dedicated_keys" | "untyped_shared_key_compat"
        ) {
            return Err(config_err(format!(
                "trust must be \"typed\", \"dedicated_keys\" or \"untyped_shared_key_compat\", \
                 got '{}'",
                escape_untrusted_quoted(trust, 64)
            )));
        }
        if typ.is_some() && trust != "typed" {
            return Err(config_err("typ is only used with trust=\"typed\""));
        }
        if typ.is_some_and(|t| t.trim().is_empty()) {
            return Err(config_err("typ must not be empty"));
        }
        if allowed_algorithms.is_empty() {
            return Err(config_err("allowed_algorithms must not be empty"));
        }
        if issuer.is_empty() {
            return Err(config_err("issuer must not be empty"));
        }
        if client_id.is_empty() {
            return Err(config_err("client_id must not be empty"));
        }
        let leeway = seconds("leeway", leeway)?;
        if leeway.is_some_and(|l| l > MAX_ID_TOKEN_LEEWAY) {
            return Err(config_err(format!(
                "JARM leeway must be at most {MAX_ID_TOKEN_LEEWAY} seconds"
            )));
        }
        let algs = parse_algorithms(&allowed_algorithms)?;
        let source = JwksSource::from_py(jwks)?;
        source.check_issuer(issuer)?;
        source.check_algorithms(py, &algs)?;

        // Shape checks before any key-set fetch.
        let token = match (self.inner.jarm_response(), self.inner.jarm_verified()) {
            (Some(t), false) => t,
            (Some(_), true) => return Err(bad_response("JARM response is already verified")),
            (None, _) => return Err(bad_response("response is not a JARM response")),
        };
        // Five dot-separated segments is a compact JWE.
        if token.split('.').count() == 5 {
            return Err(bad_response("encrypted JARM not supported"));
        }

        // A cache refreshes once if the response's `kid` is unknown.
        // An unknown `kid` after that refresh is an authentication failure of
        // the response, so it is an `AuthnError` here (`JwksCache` itself
        // raises `UnknownKeyError`). Every other resolve error is unchanged.
        let set = source.resolve(py, token, issuer).map_err(|e| {
            if e.is_instance_of::<UnknownKeyError>(py) {
                let msg = e.value(py).to_string();
                let new = with_code(py, AuthnError::new_err(msg), "unknown_kid");
                new.set_cause(py, Some(e));
                new
            } else {
                e
            }
        })?;
        let set = prepare_mac_keys(py, &set, token, &algs, KeySelection::Named)?;
        let mut options = gcb::JarmOptions::new(issuer, client_id, &algs);
        options = match (trust, typ) {
            ("typed", Some(t)) => options.with_expected_typ(t),
            ("typed", None) => options,
            ("dedicated_keys", _) => options.with_dedicated_keys(),
            _ => options.allow_untyped_shared_keys(),
        };
        if let Some(l) = leeway {
            options = options.with_leeway(l);
        }
        let inner = self.inner.verify_jarm(&set, &options).map_err(err)?;

        // Core keeps only its own escaped description for a verified JARM
        // response. Take the raw value from the token and escape it with the
        // binding's escaper. Reading claims without verification is safe ONLY
        // here: the signature, `iss`, `aud` and `exp` were just verified over
        // this exact token.
        let error_description_safe = gj::peek_claims_unverified(token)
            .ok()
            .and_then(|c| match c.extra.get("error_description") {
                Some(serde_json::Value::String(d)) => Some(d.clone()),
                _ => None,
            })
            .map(|d| escape_untrusted_text(&d, ERROR_DESCRIPTION_SAFE_MAX));
        Ok(AuthorizationResponse::new(
            inner,
            self.transport,
            error_description_safe,
        ))
    }

    fn __repr__(&self) -> String {
        let quoted = |v: Option<&str>| match v {
            Some(s) => format!("'{}'", escape_untrusted_quoted(s, 128)),
            None => "None".to_string(),
        };
        let set = |v: Option<&str>| if v.is_some() { "<set>" } else { "None" };
        format!(
            "AuthorizationResponse(is_error={}, error={}, code={}, state={}, iss={}, response={}, response_mode='{}')",
            if self.inner.is_error() { "True" } else { "False" },
            quoted(self.inner.error()),
            set(self.inner.code()),
            set(self.inner.state()),
            quoted(self.inner.iss()),
            set(self.inner.jarm_response()),
            self.transport,
        )
    }
}

fn response_mode_name(mode: &str) -> PyResult<&'static str> {
    match mode {
        "query" => Ok("query"),
        "fragment" => Ok("fragment"),
        "form_post" => Ok("form_post"),
        other => Err(config_err(format!(
            "response_mode must be \"query\", \"fragment\" or \"form_post\", got {:?}",
            escape_untrusted_text(other, 32)
        ))),
    }
}

const SHAPES: &str = "an http.HttpRequestData, a list of (str, str) pairs, a \
multi-dict mapping of str to list[str] (the urllib.parse.parse_qs shape), or an \
object with a .lists() method such as a werkzeug MultiDict";

/// The protocol parameters that may be named in an error message. Any other
/// name is attacker-chosen and is never echoed.
const KNOWN_PARAMS: [&str; 7] = [
    "code",
    "state",
    "error",
    "error_description",
    "error_uri",
    "iss",
    "response",
];

/// Text of a parameter name. `Err(None)` means "not a str" (the caller raises
/// its own `TypeError`); a lone surrogate is per-request input and becomes a
/// `BadRequestError` that never echoes the name.
fn param_name(obj: &Bound<'_, PyAny>) -> Result<String, Option<PyErr>> {
    let s = obj.cast::<pyo3::types::PyString>().map_err(|_| None)?;
    s.to_cow().map(|c| c.into_owned()).map_err(|_| {
        Some(bad_response(
            "an authorization response parameter name must not contain lone surrogates",
        ))
    })
}

/// Text of the value of parameter `name`. `None` means "not a str"; a lone
/// surrogate is a `BadRequestError` that names the parameter only when it is
/// a known protocol parameter, and never echoes the value.
fn param_value(obj: &Bound<'_, PyAny>, name: &str) -> Option<PyResult<String>> {
    let s = obj.cast::<pyo3::types::PyString>().ok()?;
    Some(s.to_cow().map(|c| c.into_owned()).map_err(|_| {
        let label = if KNOWN_PARAMS.contains(&name) {
            name
        } else {
            "a request parameter"
        };
        bad_response(format!("{label} must not contain lone surrogates"))
    }))
}

/// Ordered `(str, str)` pairs from a list or tuple (any sequence, never a set,
/// generator or dict view) of 2-tuples. Shape faults, including a non-`str`
/// name or value, are `TypeError`; a lone surrogate in a name or value is
/// `BadRequestError`.
fn flatten_pairs(params: &Bound<'_, PyAny>) -> PyResult<Vec<(String, String)>> {
    let shape = || PyTypeError::new_err(format!("params must be {SHAPES}"));
    if params.is_instance_of::<pyo3::types::PyString>() || params.is_instance_of::<PyDict>() {
        return Err(shape());
    }
    let seq = params.cast::<PySequence>().map_err(|_| shape())?;
    let mut pairs = Vec::new();
    for item in seq.try_iter().map_err(|_| shape())? {
        let item = item.map_err(|_| shape())?;
        let (k, v): (Bound<'_, PyAny>, Bound<'_, PyAny>) = item.extract().map_err(|_| shape())?;
        // Both type checks come before any surrogate check.
        if !k.is_instance_of::<pyo3::types::PyString>()
            || !v.is_instance_of::<pyo3::types::PyString>()
        {
            return Err(shape());
        }
        let key = param_name(&k).map_err(|e| e.unwrap_or_else(shape))?;
        let value = param_value(&v, &key).ok_or_else(shape)??;
        pairs.push((key, value));
    }
    Ok(pairs)
}

/// Flatten `(name, [values])` items, keeping duplicates. A non-list value
/// names its key in the `TypeError`.
fn flatten_multi<'py>(
    items: impl Iterator<Item = PyResult<Bound<'py, PyAny>>>,
    owner: &Bound<'py, PyAny>,
) -> PyResult<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    for item in items {
        let item = item?;
        let (k, v): (Bound<'_, PyAny>, Bound<'_, PyAny>) = item.extract()?;
        if !k.is_instance_of::<pyo3::types::PyString>() {
            return Err(PyTypeError::new_err(
                "authorization response parameter names must be str",
            ));
        }
        let key = param_name(&k);
        if !(v.is_instance_of::<PyList>() || v.is_instance_of::<PyTuple>()) {
            let subclass = !owner.is_exact_instance_of::<PyDict>();
            let hint = if subclass {
                format!(
                    " ({} is a dict subclass whose items() yields one value per key; pass \
                     request.args.items(multi=True) (a list of pairs) or request.args.lists())",
                    owner.get_type().name()?
                )
            } else {
                " (a plain dict discards duplicate parameters)".to_string()
            };
            return Err(PyTypeError::new_err(format!(
                "params is a mapping with a non-list value for key '{}'{hint}; params must be {SHAPES}",
                escape_untrusted_text(key.as_deref().unwrap_or("?"), 64)
            )));
        }
        // Value types are checked before the key or any value is tested for
        // lone surrogates: a non-str value is a programmer error.
        let mut raw = Vec::new();
        for value in v.try_iter()? {
            let value = value?;
            if !value.is_instance_of::<pyo3::types::PyString>() {
                return Err(PyTypeError::new_err(
                    "authorization response parameter values must be str",
                ));
            }
            raw.push(value);
        }
        let shape = || PyTypeError::new_err(format!("params must be {SHAPES}"));
        let key = key.map_err(|e| e.unwrap_or_else(shape))?;
        for value in raw {
            let value = param_value(&value, &key).ok_or_else(shape)??;
            pairs.push((key.clone(), value));
        }
    }
    Ok(pairs)
}

/// Collect the ordered parameter pairs and the response mode of `params`.
fn response_pairs(
    params: &Bound<'_, PyAny>,
    response_mode: Option<&str>,
) -> PyResult<(Vec<(String, String)>, &'static str)> {
    let requested = response_mode.map(response_mode_name).transpose()?;
    if params.is_instance_of::<crate::http::HttpRequestData>() {
        let request = params.extract::<PyRef<'_, crate::http::HttpRequestData>>()?;
        let lossy = |name: &str| {
            PyTypeError::new_err(format!(
                "HttpRequestData.{name} was built from a mapping, which discards duplicate \
                 authorization-response parameters; build it from a list of (str, str) pairs \
                 (request.args.items(multi=True), request.GET.lists() flattened)"
            ))
        };
        let method: String = params.getattr("method")?.extract()?;
        let query: Vec<(String, String)> = params.getattr("query_pairs")?.extract()?;
        let form: Vec<(String, String)> = params.getattr("form_pairs")?.extract()?;
        let has_protocol =
            |v: &[(String, String)]| v.iter().any(|(k, _)| RESPONSE_PARAMS.contains(&k.as_str()));
        let (pairs, mode) = if method.eq_ignore_ascii_case("GET") {
            if request.query_is_lossy() {
                return Err(lossy("query"));
            }
            if has_protocol(&form) {
                return Err(bad_response(
                    "authorization response parameters must not appear in the body of a query callback",
                ));
            }
            (query, "query")
        } else if method.eq_ignore_ascii_case("POST") {
            if request.form_is_lossy() {
                return Err(lossy("form"));
            }
            if has_protocol(&query) {
                return Err(bad_response(
                    "authorization response parameters must not appear in the query string of a form_post callback",
                ));
            }
            if form.is_empty() {
                return Err(bad_response(
                    "a form_post callback needs a form body: parse the form before building \
                     the HttpRequestData (no form parameters were found)",
                ));
            }
            (form, "form_post")
        } else {
            return Err(bad_response(
                "an authorization response arrives by GET or POST",
            ));
        };
        if let Some(r) = requested {
            if r != mode {
                return Err(config_err(format!(
                    "response_mode {r:?} does not match the request ({method} is {mode:?}); \
                     omit response_mode for an HttpRequestData"
                )));
            }
        }
        return Ok((pairs, mode));
    }
    let mode = requested.unwrap_or("query");
    // Duck-typed multi-dict (werkzeug MultiDict): lists() yields (key, [values]).
    if let Ok(lists) = params.getattr("lists") {
        if lists.is_callable() {
            let pairs = flatten_multi(lists.call0()?.try_iter()?, params)?;
            return Ok((pairs, mode));
        }
    }
    if let Ok(mapping) = params.cast::<PyMapping>() {
        let pairs = flatten_multi(mapping.items()?.try_iter()?, params)?;
        return Ok((pairs, mode));
    }
    let pairs = flatten_pairs(params)?;
    Ok((pairs, mode))
}

/// Parse the authorization response (the callback) of an authorization
/// request, fail closed.
///
/// `params` is an `http.HttpRequestData` (GET uses `query_pairs`, POST uses
/// `form_pairs` with mode `form_post`; a protocol parameter in the other
/// channel, the query string of a POST or the body of a GET, raises), an
/// ordered list of `(str, str)` pairs, a multi-dict `{name: [values]}` like
/// `urllib.parse.parse_qs` returns, or an object with a `.lists()` method
/// (werkzeug `MultiDict`). A plain `dict[str, str]` raises `TypeError`
/// because a mapping discards duplicate parameters. `response_mode` (`"query"`, `"fragment"` or
/// `"form_post"`) labels list and multi-dict input; default `"query"`.
///
/// Raises `BadRequestError` for a lone surrogate in a parameter name or value
/// of pairs, multi-dict or `.lists()` input (`HttpRequestData` construction
/// raises `TypeError` instead),
/// a repeated parameter, both or neither of
/// `code` and `error`, an empty `code` / `state` / `error` / `iss`, control, bidi or
/// invisible characters or backslashes in `code` / `state` / `iss`, a `code` /
/// `state` / `iss` over 2048 characters (a JARM `response` over 32768), an `error` outside RFC 6749 section
/// 5.2, and a JARM `response` unless `accept_jarm=True` (then it is exposed
/// raw and UNVERIFIED, and must be the only protocol parameter; this binding
/// has no JARM support, so verify the JWT yourself). Unknown error codes are
/// kept.
///
/// The result proves nothing by itself: compare `state` with the session,
/// check `iss` with `matches_iss`, then exchange the code.
#[pyfunction]
#[pyo3(signature = (params, *, response_mode = None, accept_jarm = false))]
fn parse_authorization_response(
    params: &Bound<'_, PyAny>,
    response_mode: Option<&str>,
    accept_jarm: bool,
) -> PyResult<AuthorizationResponse> {
    let (pairs, mode) = response_pairs(params, response_mode)?;
    jarm_prechecks(&pairs, accept_jarm)?;
    let mut opts = gcb::AuthorizationResponseOptions::new();
    if accept_jarm {
        opts = opts.accept_unverified_jarm();
    }
    let inner = gcb::parse_authorization_response(&pairs, &opts).map_err(err)?;
    // The core rejected repeats, so at most one raw description exists.
    let error_description_safe = pairs
        .iter()
        .find(|(k, _)| k == "error_description")
        .map(|(_, d)| escape_untrusted_text(d, ERROR_DESCRIPTION_SAFE_MAX));
    Ok(AuthorizationResponse::new(
        inner,
        mode,
        error_description_safe,
    ))
}

impl AuthorizationResponse {
    /// Wrap a core response, applying the `error_uri` fragment filter.
    fn new(
        inner: gcb::AuthorizationResponse,
        transport: &'static str,
        error_description_safe: Option<String>,
    ) -> Self {
        // A URL with a fragment is never exposed.
        let error_uri = inner
            .error_uri()
            .filter(|u| url::Url::parse(u).is_ok_and(|p| p.fragment().is_none()))
            .map(str::to_string);
        Self {
            inner,
            transport,
            error_description_safe,
            error_uri,
        }
    }
}

/// The binding's own wording for the two JARM refusals (default-off and
/// `response` alongside other parameters). Additive: it only fires when no
/// parameter repeats, so the core reports a repeat first, as before.
fn jarm_prechecks(pairs: &[(String, String)], accept_jarm: bool) -> PyResult<()> {
    let count = |n: &str| pairs.iter().filter(|(k, _)| k == n).count();
    if RESPONSE_PARAMS.iter().any(|n| count(n) > 1) || count("response") == 0 {
        return Ok(());
    }
    if !accept_jarm {
        return Err(bad_response(
            "JARM response parameter is not supported; pass accept_jarm=True only if you \
             verify the JWT yourself",
        ));
    }
    if RESPONSE_PARAMS
        .iter()
        .any(|n| *n != "response" && count(n) > 0)
    {
        return Err(bad_response(
            "a JARM response carries every parameter inside the JWT: code, state, error, \
             error_description, error_uri and iss must not appear alongside response",
        ));
    }
    Ok(())
}

/// Render untrusted OP-advertised values for a message: each escaped and
/// capped, at most 20 shown.
fn show_list(items: &[String]) -> String {
    let mut parts: Vec<String> = items
        .iter()
        .take(20)
        .map(|i| format!("'{}'", escape_untrusted_quoted(i, 64)))
        .collect();
    if items.len() > 20 {
        parts.push(format!("... ({} more)", items.len() - 20));
    }
    format!("[{}]", parts.join(", "))
}

/// Compare what the RP intends to use with what the OP's discovery document
/// advertises. Pure and advisory: no I/O, nothing is enforced, and the
/// metadata is untrusted, unauthenticated data from the OP.
///
/// `provider` is a `ProviderInfo` built by `discover` /
/// `ProviderInfo.from_metadata` (one without metadata raises `ConfigError`)
/// or a `ProviderMetadata`. Always checked: `"code"` in
/// `response_types_supported`. Checked when given: `pkce=True` (RP will send
/// an S256 challenge; `None`/`False` skip it) against
/// `code_challenge_methods_supported`; `algorithms` (the RP's allowed
/// id_token algorithms, must intersect `id_token_signing_alg_values_supported`);
/// `scopes` against `scopes_supported`; `acr_values` against
/// `acr_values_supported`; `client.auth_method` against
/// `token_endpoint_auth_methods_supported`.
///
/// Two `algorithms` rules mirror ADR 0006 (the function stays advisory):
/// `none` (case-insensitive) is always a mismatch ("fix the RP config, not
/// the OP") and never counts as an intersection match; `HS256/384/512` are a
/// mismatch unless `shared_secret_keys=True` (the RP verifies with a key set
/// derived from the client_secret, OIDC Core 10.1; they are refused with
/// `JwksCache` / published JWKS) and are ignored by the intersection check in
/// that case. With `shared_secret_keys=True` HS* takes part in the normal
/// intersection. If no other algorithm remains, the intersection check is
/// skipped.
///
/// Not checked: `grant_types_supported`, `response_modes_supported`,
/// `pkce=False`/`None`, DPoP, request-object, claims or any other metadata.
///
/// Returns human-readable strings, empty when nothing contradicts the
/// document. A string starting with `"not advertised:"` is informational: the
/// OP lists no values (absent or empty) for a check that was performed, so it
/// can be neither confirmed nor refuted. No default is assumed for those
/// lists (in particular not `RS256` for `id_token_signing_alg_values_supported`).
/// Any other string is a mismatch.
///
/// Exception: when `token_endpoint_auth_methods_supported` is absent or empty
/// (indistinguishable after parsing, so both count as absent) the spec default
/// `["client_secret_basic"]` (OIDC Discovery 1.0 section 3, RFC 8414 section
/// 2) is assumed: any other `client.auth_method` is a real mismatch.
#[pyfunction]
#[pyo3(signature = (provider, *, client = None, pkce = None, algorithms = None, scopes = None, acr_values = None, shared_secret_keys = false))]
fn check_rp_compatibility(
    provider: &Bound<'_, PyAny>,
    client: Option<&RpClient>,
    pkce: Option<bool>,
    algorithms: Option<Vec<String>>,
    scopes: Option<Vec<String>>,
    acr_values: Option<Vec<String>>,
    shared_secret_keys: bool,
) -> PyResult<Vec<String>> {
    let md: gm::ProviderMetadata = if let Ok(info) = provider.cast::<ProviderInfo>() {
        match &info.get().metadata {
            Some(m) => m.inner.clone(),
            None => {
                return Err(config_err(
                    "ProviderInfo has no metadata; build it with rp.discover / \
                     ProviderInfo.from_metadata",
                ))
            }
        }
    } else if let Ok(m) = provider.cast::<ProviderMetadata>() {
        m.borrow().inner.clone()
    } else {
        return Err(PyTypeError::new_err(
            "provider must be a ProviderInfo or a ProviderMetadata",
        ));
    };
    if matches!(&algorithms, Some(a) if a.is_empty()) {
        return Err(config_err("algorithms must not be empty"));
    }
    let acr_supported: Vec<String> = md
        .extra
        .get("acr_values_supported")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    let mut out = Vec::new();
    let na = |field: &str, why: &str| format!("not advertised: {field} ({why})");

    if md.response_types_supported.is_empty() {
        out.push(na(
            "response_types_supported",
            "cannot confirm the authorization code flow",
        ));
    } else if !md.response_types_supported.iter().any(|t| t == "code") {
        out.push(format!(
            "response_types_supported does not include 'code' (OP advertises {})",
            show_list(&md.response_types_supported)
        ));
    }
    if pkce == Some(true) {
        let m = &md.code_challenge_methods_supported;
        if m.is_empty() {
            out.push(na(
                "code_challenge_methods_supported",
                "cannot confirm PKCE S256 support",
            ));
        } else if !m.iter().any(|x| x == "S256") {
            out.push(format!(
                "code_challenge_methods_supported does not include 'S256' (OP advertises {})",
                show_list(m)
            ));
        }
    }
    if let Some(algs) = &algorithms {
        // ADR 0006: `none` is always refused; HS* only works with a key set
        // derived from the client_secret, which this function cannot see.
        let is_none = |a: &String| a.eq_ignore_ascii_case("none");
        let is_hs = |a: &String| {
            ["HS256", "HS384", "HS512"]
                .iter()
                .any(|h| a.eq_ignore_ascii_case(h))
        };
        for a in algs.iter().filter(|a| is_none(a)) {
            out.push(format!(
                "allowed id_token algorithm '{}' is always refused by this library \
                 (ADR 0006): fix the RP config, not the OP",
                escape_untrusted_quoted(a, 64)
            ));
        }
        if !shared_secret_keys {
            let hs: Vec<String> = algs.iter().filter(|a| is_hs(a)).cloned().collect();
            if !hs.is_empty() {
                out.push(format!(
                    "allowed id_token algorithms {} are only usable with a key set derived \
                     from the client_secret (OIDC Core 10.1) and are refused with JwksCache / \
                     published JWKS (ADR 0006); pass shared_secret_keys=True if that is how \
                     you verify, otherwise remove them",
                    show_list(&hs)
                ));
            }
        }
        let relevant: Vec<String> = algs
            .iter()
            .filter(|a| !is_none(a) && (shared_secret_keys || !is_hs(a)))
            .cloned()
            .collect();
        if !relevant.is_empty() {
            let sup = &md.id_token_signing_alg_values_supported;
            if sup.is_empty() {
                out.push(na(
                    "id_token_signing_alg_values_supported",
                    "cannot confirm a usable id_token signing algorithm",
                ));
            } else if !relevant.iter().any(|a| sup.contains(a)) {
                out.push(format!(
                    "none of the allowed id_token algorithms {} is in \
                     id_token_signing_alg_values_supported (OP advertises {})",
                    show_list(&relevant),
                    show_list(sup)
                ));
            }
        }
    }
    if let Some(wanted) = &scopes {
        let sup = &md.scopes_supported;
        if sup.is_empty() {
            out.push(na(
                "scopes_supported",
                "cannot confirm the requested scopes",
            ));
        } else {
            let missing: Vec<String> = wanted
                .iter()
                .filter(|w| !sup.contains(w))
                .cloned()
                .collect();
            if !missing.is_empty() {
                out.push(format!(
                    "scopes not in scopes_supported: {} (OP advertises {})",
                    show_list(&missing),
                    show_list(sup)
                ));
            }
        }
    }
    if let Some(wanted) = &acr_values {
        if acr_supported.is_empty() {
            out.push(na(
                "acr_values_supported",
                "cannot confirm the requested acr_values",
            ));
        } else {
            let missing: Vec<String> = wanted
                .iter()
                .filter(|w| !acr_supported.contains(w))
                .cloned()
                .collect();
            if !missing.is_empty() {
                out.push(format!(
                    "acr_values not in acr_values_supported: {} (OP advertises {})",
                    show_list(&missing),
                    show_list(&acr_supported)
                ));
            }
        }
    }
    if let Some(client) = client {
        let method = auth_method_name(&client.inner.auth);
        let sup = &md.token_endpoint_auth_methods_supported;
        if sup.is_empty() {
            if method != "client_secret_basic" {
                out.push(format!(
                    "client auth_method '{method}' is not usable: \
                     token_endpoint_auth_methods_supported is absent, so the spec default \
                     ['client_secret_basic'] was assumed"
                ));
            }
        } else if !sup.iter().any(|s| s == method) {
            out.push(format!(
                "client auth_method '{method}' is not in token_endpoint_auth_methods_supported \
                 (OP advertises {})",
                show_list(sup)
            ));
        }
    }
    Ok(out)
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "rp")?;
    m.add_class::<ProviderInfo>()?;
    m.add_class::<RpClient>()?;
    m.add_class::<TokenSet>()?;
    m.add_class::<AuthorizationResponse>()?;
    m.add_class::<JwksCache>()?;
    m.add_class::<DiscoveryCache>()?;
    m.add_function(wrap_pyfunction!(authorization_url, &m)?)?;
    m.add_function(wrap_pyfunction!(signed_request_object, &m)?)?;
    m.add_function(wrap_pyfunction!(begin, &m)?)?;
    m.add("BeginResult", begin_result_type(py)?)?;
    m.add_function(wrap_pyfunction!(claims_audiences, &m)?)?;
    m.add_function(wrap_pyfunction!(check_rp_compatibility, &m)?)?;
    m.add_function(wrap_pyfunction!(discover, &m)?)?;
    m.add_function(wrap_pyfunction!(end_session_url, &m)?)?;
    m.add_function(wrap_pyfunction!(fetch_jwks, &m)?)?;
    m.add_function(wrap_pyfunction!(exchange_code, &m)?)?;
    m.add_function(wrap_pyfunction!(verify_id_token, &m)?)?;
    m.add_function(wrap_pyfunction!(fetch_userinfo, &m)?)?;
    m.add_function(wrap_pyfunction!(build_client_assertion, &m)?)?;
    m.add_function(wrap_pyfunction!(claims_to_attributes, &m)?)?;
    m.add_function(wrap_pyfunction!(validate_issuer, &m)?)?;
    m.add_function(wrap_pyfunction!(validate_redirect_uri_syntax, &m)?)?;
    m.add_function(wrap_pyfunction!(validate_service_endpoint, &m)?)?;
    m.add_function(wrap_pyfunction!(asymmetric_algorithms, &m)?)?;
    m.add_function(wrap_pyfunction!(parse_authorization_response, &m)?)?;
    m.add("MAX_ID_TOKEN_LEEWAY", MAX_ID_TOKEN_LEEWAY)?;
    m.add(
        "JARM_ASYMMETRIC_ALGORITHMS",
        PyTuple::new(
            py,
            gcb::JARM_ASYMMETRIC_ALGORITHMS
                .iter()
                .map(|a| a.to_string()),
        )?,
    )?;
    m.add("JARM_TYP", gcb::JARM_TYP)?;
    Ok(())
}
