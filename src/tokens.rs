//! Bindings for `grindvakt::tokens` - the stateless token codec and its sealed
//! payloads (authorization codes, access tokens, refresh tokens).

use std::collections::BTreeMap;

use pyo3::exceptions::{PyDeprecationWarning, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use grindvakt::tokens as gt;

use crate::convert::{from_py, new_submodule, to_py};
use crate::errors::err;

/// `PyErr::warn` stacklevel naming the Python caller: native frames are not Python
/// frames, so 1 is already the frame that called the constructor (2 reports `sys:1`).
const STACKLEVEL: i32 = 1;

fn claims_map(v: Option<&Bound<'_, PyAny>>) -> PyResult<BTreeMap<String, serde_json::Value>> {
    match v {
        Some(v) if !v.is_none() => from_py(v),
        _ => Ok(BTreeMap::new()),
    }
}

/// Like [`claims_map`] but keeps "not given" (`None`) distinct from an empty map.
fn opt_claims_map(
    v: Option<&Bound<'_, PyAny>>,
) -> PyResult<Option<BTreeMap<String, serde_json::Value>>> {
    match v {
        Some(v) if !v.is_none() => Ok(Some(from_py(v)?)),
        _ => Ok(None),
    }
}

/// Payload sealed into an authorization code.
#[pyclass(
    module = "pygrindvakt.tokens",
    name = "AuthCodePayload",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct AuthCodePayload {
    pub inner: gt::AuthCodePayload,
}

#[pymethods]
impl AuthCodePayload {
    #[new]
    #[pyo3(signature = (*, client_id, redirect_uri, scope, sub, auth_time, exp, nonce = None,
                        code_challenge = None, code_challenge_method = None, claims = None, acr = None,
                        registration_digest = None, userinfo_claims = None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        client_id: String,
        redirect_uri: String,
        scope: String,
        sub: String,
        auth_time: u64,
        exp: u64,
        nonce: Option<String>,
        code_challenge: Option<String>,
        code_challenge_method: Option<String>,
        claims: Option<&Bound<'_, PyAny>>,
        acr: Option<String>,
        registration_digest: Option<String>,
        userinfo_claims: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        if registration_digest.is_none() {
            // Only the Python constructor warns; codes opened by the codec and
            // from_dict build the Rust payload directly and stay silent.
            PyErr::warn(
                py,
                &py.get_type::<PyDeprecationWarning>(),
                c"AuthCodePayload without registration_digest skips the client-registration \
                  binding check at the token endpoint, so a rotated secret or key does not \
                  invalidate outstanding codes; it will become required in a future release. \
                  Pass registration_digest=client.registration_fingerprint() or use \
                  Provider.authorization_redirect_with_authorized_claims",
                STACKLEVEL,
            )?;
        }
        Ok(Self {
            inner: gt::AuthCodePayload {
                client_id,
                redirect_uri,
                scope,
                sub,
                nonce,
                code_challenge,
                code_challenge_method,
                claims: claims_map(claims)?,
                auth_time,
                exp,
                acr,
                registration_digest,
                userinfo_claims: opt_claims_map(userinfo_claims)?,
            },
        })
    }
    #[staticmethod]
    fn from_dict(d: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self {
            inner: from_py(d)
                .map_err(|e| PyValueError::new_err(format!("invalid AuthCodePayload: {e}")))?,
        })
    }
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner)
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
    #[getter]
    fn sub(&self) -> &str {
        &self.inner.sub
    }
    #[getter]
    fn nonce(&self) -> Option<&str> {
        self.inner.nonce.as_deref()
    }
    #[getter]
    fn code_challenge(&self) -> Option<&str> {
        self.inner.code_challenge.as_deref()
    }
    #[getter]
    fn code_challenge_method(&self) -> Option<&str> {
        self.inner.code_challenge_method.as_deref()
    }
    #[getter]
    fn claims<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner.claims)
    }
    #[getter]
    fn auth_time(&self) -> u64 {
        self.inner.auth_time
    }
    #[getter]
    fn exp(&self) -> u64 {
        self.inner.exp
    }
    #[getter]
    fn acr(&self) -> Option<&str> {
        self.inner.acr.as_deref()
    }
    /// Fingerprint of the client registration the code was issued against;
    /// `None` for codes sealed before 0.6.0 (the check is skipped for those).
    #[getter]
    fn registration_digest(&self) -> Option<&str> {
        self.inner.registration_digest.as_deref()
    }
    /// Claims destined for the UserInfo response. `None` means use `claims`;
    /// `{}` releases none.
    #[getter]
    fn userinfo_claims<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        self.inner
            .userinfo_claims
            .as_ref()
            .map(|m| to_py(py, m))
            .transpose()
    }
    fn __repr__(&self) -> String {
        format!(
            "AuthCodePayload(client_id={:?}, sub={:?}, scope={:?}, exp={})",
            self.inner.client_id, self.inner.sub, self.inner.scope, self.inner.exp
        )
    }
}

/// Payload sealed into an access token.
#[pyclass(
    module = "pygrindvakt.tokens",
    name = "AccessTokenPayload",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct AccessTokenPayload {
    pub inner: gt::AccessTokenPayload,
}

#[pymethods]
impl AccessTokenPayload {
    #[new]
    #[pyo3(signature = (*, client_id, sub, scope, exp, claims = None, cnf_jkt = None))]
    fn new(
        client_id: String,
        sub: String,
        scope: String,
        exp: u64,
        claims: Option<&Bound<'_, PyAny>>,
        cnf_jkt: Option<String>,
    ) -> PyResult<Self> {
        Ok(Self {
            inner: gt::AccessTokenPayload {
                client_id,
                sub,
                scope,
                claims: claims_map(claims)?,
                exp,
                cnf_jkt,
            },
        })
    }
    #[staticmethod]
    fn from_dict(d: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self {
            inner: from_py(d)
                .map_err(|e| PyValueError::new_err(format!("invalid AccessTokenPayload: {e}")))?,
        })
    }
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner)
    }
    #[getter]
    fn client_id(&self) -> &str {
        &self.inner.client_id
    }
    #[getter]
    fn sub(&self) -> &str {
        &self.inner.sub
    }
    #[getter]
    fn scope(&self) -> &str {
        &self.inner.scope
    }
    #[getter]
    fn claims<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner.claims)
    }
    #[getter]
    fn exp(&self) -> u64 {
        self.inner.exp
    }
    /// DPoP key thumbprint the token is bound to (`cnf.jkt`), if any.
    #[getter]
    fn cnf_jkt(&self) -> Option<&str> {
        self.inner.cnf_jkt.as_deref()
    }
    fn __repr__(&self) -> String {
        format!(
            "AccessTokenPayload(client_id={:?}, sub={:?}, scope={:?}, exp={}, cnf_jkt={:?})",
            self.inner.client_id,
            self.inner.sub,
            self.inner.scope,
            self.inner.exp,
            self.inner.cnf_jkt
        )
    }
}

/// Payload sealed into a refresh token.
#[pyclass(
    module = "pygrindvakt.tokens",
    name = "RefreshTokenPayload",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct RefreshTokenPayload {
    pub inner: gt::RefreshTokenPayload,
}

#[pymethods]
impl RefreshTokenPayload {
    #[new]
    #[pyo3(signature = (*, client_id, sub, scope, auth_time, exp, nonce = None, claims = None,
                        acr = None, cnf_jkt = None, userinfo_claims = None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        client_id: String,
        sub: String,
        scope: String,
        auth_time: u64,
        exp: u64,
        nonce: Option<String>,
        claims: Option<&Bound<'_, PyAny>>,
        acr: Option<String>,
        cnf_jkt: Option<String>,
        userinfo_claims: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        Ok(Self {
            inner: gt::RefreshTokenPayload {
                client_id,
                sub,
                scope,
                nonce,
                claims: claims_map(claims)?,
                auth_time,
                exp,
                acr,
                cnf_jkt,
                userinfo_claims: opt_claims_map(userinfo_claims)?,
            },
        })
    }
    #[staticmethod]
    fn from_dict(d: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self {
            inner: from_py(d)
                .map_err(|e| PyValueError::new_err(format!("invalid RefreshTokenPayload: {e}")))?,
        })
    }
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner)
    }
    #[getter]
    fn client_id(&self) -> &str {
        &self.inner.client_id
    }
    #[getter]
    fn sub(&self) -> &str {
        &self.inner.sub
    }
    #[getter]
    fn scope(&self) -> &str {
        &self.inner.scope
    }
    #[getter]
    fn nonce(&self) -> Option<&str> {
        self.inner.nonce.as_deref()
    }
    #[getter]
    fn claims<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner.claims)
    }
    #[getter]
    fn auth_time(&self) -> u64 {
        self.inner.auth_time
    }
    #[getter]
    fn exp(&self) -> u64 {
        self.inner.exp
    }
    #[getter]
    fn acr(&self) -> Option<&str> {
        self.inner.acr.as_deref()
    }
    #[getter]
    fn cnf_jkt(&self) -> Option<&str> {
        self.inner.cnf_jkt.as_deref()
    }
    /// Claims destined for the UserInfo response. `None` means use `claims`;
    /// `{}` releases none.
    #[getter]
    fn userinfo_claims<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        self.inner
            .userinfo_claims
            .as_ref()
            .map(|m| to_py(py, m))
            .transpose()
    }
    fn __repr__(&self) -> String {
        format!(
            "RefreshTokenPayload(client_id={:?}, sub={:?}, scope={:?}, exp={})",
            self.inner.client_id, self.inner.sub, self.inner.scope, self.inner.exp
        )
    }
}

/// Seals / opens authorization codes, access tokens and refresh tokens as
/// JWE (`dir` + `A256GCM`) under keys derived from the OP secret via HKDF.
///
/// `previous_secrets` are tried on open so tokens sealed under an old secret
/// keep validating during key rotation.
///
/// SECURITY: secrets are Python `str`s and cannot be zeroized after use.
#[pyclass(
    module = "pygrindvakt.tokens",
    name = "TokenCodec",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct TokenCodec {
    pub inner: gt::TokenCodec,
}

#[pymethods]
impl TokenCodec {
    #[new]
    #[pyo3(signature = (secret, previous_secrets = None))]
    fn new(secret: &str, previous_secrets: Option<Vec<String>>) -> Self {
        let mut codec = gt::TokenCodec::new(secret);
        if let Some(prev) = previous_secrets {
            codec = codec.with_previous_secrets(&prev);
        }
        Self { inner: codec }
    }
    fn seal_code(&self, payload: &AuthCodePayload) -> PyResult<String> {
        self.inner.seal_code(&payload.inner).map_err(err)
    }
    /// Open an authorization code (checks the type tag and expiry).
    fn open_code(&self, token: &str) -> PyResult<AuthCodePayload> {
        self.inner
            .open_code(token)
            .map(|inner| AuthCodePayload { inner })
            .map_err(err)
    }
    fn seal_access_token(&self, payload: &AccessTokenPayload) -> PyResult<String> {
        self.inner.seal_access_token(&payload.inner).map_err(err)
    }
    fn open_access_token(&self, token: &str) -> PyResult<AccessTokenPayload> {
        self.inner
            .open_access_token(token)
            .map(|inner| AccessTokenPayload { inner })
            .map_err(err)
    }
    fn seal_refresh_token(&self, payload: &RefreshTokenPayload) -> PyResult<String> {
        self.inner.seal_refresh_token(&payload.inner).map_err(err)
    }
    fn open_refresh_token(&self, token: &str) -> PyResult<RefreshTokenPayload> {
        self.inner
            .open_refresh_token(token)
            .map(|inner| RefreshTokenPayload { inner })
            .map_err(err)
    }
    fn __repr__(&self) -> &'static str {
        "TokenCodec(<secret>)"
    }
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "tokens")?;
    m.add_class::<AuthCodePayload>()?;
    m.add_class::<AccessTokenPayload>()?;
    m.add_class::<RefreshTokenPayload>()?;
    m.add_class::<TokenCodec>()?;
    Ok(())
}
