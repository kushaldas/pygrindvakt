//! Bindings for `grindvakt::http` - the framework-agnostic request / response
//! types, the outbound `HttpClient` protocol, and the built-in reqwest client.
//!
//! `HttpRequestData` is what a web-framework adapter builds from the incoming
//! request (see `examples/`); `Response` is what the application turns back
//! into its framework's response type. Neither depends on any framework.
//!
//! Outbound HTTP (RP discovery, code exchange, federation fetches) goes through
//! an object satisfying the `HttpClient` protocol: either the built-in
//! `ReqwestClient` or any Python object with
//!
//! ```text
//! get(url: str) -> tuple[int, bytes, str | None]
//! post_form(url: str, form: list[tuple[str, str]], headers: list[tuple[str, str]])
//!     -> tuple[int, bytes, str | None]
//! ```
//!
//! A client may also provide an optional `post_json(url: str, body: Any,
//! headers: list[tuple[str, str]]) -> tuple[int, bytes, str | None]`, where
//! `body` is a JSON-compatible Python object. Without it, JSON POSTs through
//! that client fail with a configuration error.
//!
//! A client may additionally support request headers on GET (needed for
//! `fetch_userinfo(method="GET")`), decided once when the client is first
//! used: either `get(url, headers=...)` (a `headers` parameter or `**kwargs`)
//! or a callable `get_with_headers(url, headers)`, which is preferred when
//! present. There is no call-and-retry fallback.
//!
//! SECURITY: an injected client is responsible for timeouts, for *not*
//! following redirects (a 307/308 would re-send token-endpoint form bodies and
//! Bearer tokens cross-origin; at minimum `Authorization` must be stripped on
//! a cross-origin redirect), and for bounding response sizes. The built-in
//! client never follows redirects, for any request type, and does all three.
//!
//! A Python client runs on the thread driving the call, holding the GIL, so an
//! instance shared across threads must be thread-safe itself; calling back into
//! pygrindvakt from it is supported at the cost of a helper thread per nested
//! call (see `runtime::block_on`).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyMapping, PyModule};

use grindvakt::http as gh;
use grindvakt::http::{HttpClient, HttpFetchResponse as RsFetch};
use grindvakt::Error as RsError;

use crate::convert::{
    from_py, log_unraisable, new_submodule, parameter_pairs, require_methods, to_py,
};
use crate::errors::{bad_request_err, err, internal_err, with_code, InternalError};

// ---------------------------------------------------------------------------
// HttpRequestData
// ---------------------------------------------------------------------------

/// A parsed inbound HTTP request, normalized for grindvakt.
///
/// Build one from your framework's request object. `headers` keys must be
/// lower-cased. Pass query/form pair lists from the framework so duplicate
/// OAuth parameters remain available to the protocol parser; the convenience
/// map properties retain the last value only for non-protocol application use.
#[pyclass(module = "pygrindvakt.http", name = "HttpRequestData", from_py_object)]
#[derive(Clone)]
pub struct HttpRequestData {
    pub inner: gh::HttpRequestData,
    query_pairs: Vec<(String, String)>,
    form_pairs: Vec<(String, String)>,
    /// `query` was supplied as a mapping, which may have discarded duplicate
    /// parameters; the authorization-response parser refuses such a channel.
    query_from_mapping: bool,
    form_from_mapping: bool,
}

/// Convert a `query` / `form` value to ordered pairs, also reporting whether it
/// was a mapping (which discards duplicates) rather than a sequence of pairs.
fn request_pairs(obj: &Bound<'_, PyAny>, name: &str) -> PyResult<(Vec<(String, String)>, bool)> {
    if obj.cast::<PyDict>().is_err() {
        if let Ok(mapping) = obj.cast::<PyMapping>() {
            let pairs = mapping
                .items()?
                .try_iter()?
                .map(|item| item?.extract::<(String, String)>())
                .collect::<PyResult<Vec<_>>>()?;
            return Ok((pairs, true));
        }
        return Ok((parameter_pairs(obj, name)?, false));
    }
    Ok((parameter_pairs(obj, name)?, true))
}

impl HttpRequestData {
    /// True if the query channel was built from a non-empty mapping.
    pub fn query_is_lossy(&self) -> bool {
        self.query_from_mapping && !self.query_pairs.is_empty()
    }
    /// True if the form channel was built from a non-empty mapping.
    pub fn form_is_lossy(&self) -> bool {
        self.form_from_mapping && !self.form_pairs.is_empty()
    }
}

#[pymethods]
impl HttpRequestData {
    #[new]
    #[pyo3(signature = (path = "", method = "GET", uri = "", query = None, form = None,
                        body = None, headers = None, cookies = None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        path: &str,
        method: &str,
        uri: &str,
        query: Option<&Bound<'_, PyAny>>,
        form: Option<&Bound<'_, PyAny>>,
        body: Option<&[u8]>,
        headers: Option<BTreeMap<String, String>>,
        cookies: Option<BTreeMap<String, String>>,
    ) -> PyResult<Self> {
        let (query_pairs, query_from_mapping) = query
            .map(|value| request_pairs(value, "query"))
            .transpose()?
            .unwrap_or_default();
        let (form_pairs, form_from_mapping) = form
            .map(|value| request_pairs(value, "form"))
            .transpose()?
            .unwrap_or_default();
        let headers = headers
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
        Ok(Self {
            inner: gh::HttpRequestData {
                path: path.trim_start_matches('/').to_string(),
                method: method.to_ascii_uppercase(),
                uri: uri.to_string(),
                query_pairs: query_pairs.clone(),
                query: query_pairs.iter().cloned().collect(),
                form_pairs: form_pairs.clone(),
                form: form_pairs.iter().cloned().collect(),
                body: body.map(|b| b.to_vec()).unwrap_or_default(),
                headers,
                cookies: cookies.unwrap_or_default(),
            },
            query_pairs,
            form_pairs,
            query_from_mapping,
            form_from_mapping,
        })
    }

    #[getter]
    fn path(&self) -> &str {
        &self.inner.path
    }
    #[setter]
    fn set_path(&mut self, v: &str) {
        self.inner.path = v.trim_start_matches('/').to_string();
    }
    #[getter]
    fn method(&self) -> &str {
        &self.inner.method
    }
    #[setter]
    fn set_method(&mut self, v: &str) {
        self.inner.method = v.to_ascii_uppercase();
    }
    #[getter]
    fn uri(&self) -> &str {
        &self.inner.uri
    }
    #[setter]
    fn set_uri(&mut self, v: String) {
        self.inner.uri = v;
    }
    #[getter]
    fn query(&self) -> BTreeMap<String, String> {
        self.inner.query.clone()
    }
    #[setter]
    fn set_query(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        let (pairs, from_mapping) = request_pairs(v, "query")?;
        self.inner.query = pairs.iter().cloned().collect();
        self.query_pairs = pairs;
        self.query_from_mapping = from_mapping;
        Ok(())
    }
    /// Ordered query parameters, retaining duplicates for protocol validation.
    #[getter]
    fn query_pairs(&self) -> Vec<(String, String)> {
        self.query_pairs.clone()
    }
    #[getter]
    fn form(&self) -> BTreeMap<String, String> {
        self.inner.form.clone()
    }
    #[setter]
    fn set_form(&mut self, v: &Bound<'_, PyAny>) -> PyResult<()> {
        let (pairs, from_mapping) = request_pairs(v, "form")?;
        self.inner.form = pairs.iter().cloned().collect();
        self.form_pairs = pairs;
        self.form_from_mapping = from_mapping;
        Ok(())
    }
    /// Ordered form parameters, retaining duplicates for protocol validation.
    #[getter]
    fn form_pairs(&self) -> Vec<(String, String)> {
        self.form_pairs.clone()
    }
    #[getter]
    fn body<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.body)
    }
    #[setter]
    fn set_body(&mut self, v: &[u8]) {
        self.inner.body = v.to_vec();
    }
    #[getter]
    fn headers(&self) -> BTreeMap<String, String> {
        self.inner.headers.clone()
    }
    #[setter]
    fn set_headers(&mut self, v: BTreeMap<String, String>) {
        self.inner.headers = v
            .into_iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
    }
    #[getter]
    fn cookies(&self) -> BTreeMap<String, String> {
        self.inner.cookies.clone()
    }
    #[setter]
    fn set_cookies(&mut self, v: BTreeMap<String, String>) {
        self.inner.cookies = v;
    }

    /// Look up a parameter from the query string first, then the form body.
    fn param(&self, key: &str) -> Option<String> {
        self.inner.param(key).map(String::from)
    }
    /// The value of the `Authorization` header, if present.
    fn authorization(&self) -> Option<String> {
        self.inner.authorization().map(String::from)
    }
    /// Extract a Bearer token from the Authorization header.
    fn bearer_token(&self) -> Option<String> {
        self.inner.bearer_token().map(String::from)
    }

    fn __repr__(&self) -> String {
        format!(
            "HttpRequestData(method={:?}, path={:?}, query={}, form={}, headers={})",
            self.inner.method,
            self.inner.path,
            self.inner.query.len(),
            self.inner.form.len(),
            self.inner.headers.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

/// A framework-agnostic HTTP response produced by grindvakt.
///
/// `headers` is a list of `(name, value)` pairs (multi-valued headers such as
/// `set-cookie` are supported); `body` is `bytes`.
#[pyclass(module = "pygrindvakt.http", name = "Response", from_py_object)]
#[derive(Clone)]
pub struct Response {
    pub inner: gh::Response,
}

impl Response {
    pub fn wrap(inner: gh::Response) -> Self {
        Self { inner }
    }
}

/// Response header gate (header injection): `name` must be a non-empty RFC
/// 9110 token; `value` must not hold a C0 control (HTAB allowed), DEL or NUL.
/// Neither is echoed.
fn check_response_header(name: &str, value: &str) -> PyResult<()> {
    let token = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c);
    if name.is_empty() || !name.chars().all(token) {
        return Err(bad_request_err(
            "response header name must be a non-empty RFC 9110 token",
        ));
    }
    if value.chars().any(|c| c.is_ascii_control() && c != '\t') {
        return Err(bad_request_err(
            "response header value must not contain control characters",
        ));
    }
    if name.eq_ignore_ascii_case("location") {
        check_location(value)?;
    }
    Ok(())
}

/// A `Location` value: no whitespace, control, bidi or invisible formatting
/// character and no backslash (the `url` crate and browsers read `\` as `/`).
/// Relative targets and fragments pass. Never echoed.
fn check_location(location: &str) -> PyResult<()> {
    if crate::rp::has_unsafe_uri_char(location) {
        return Err(bad_request_err(
            "redirect location must not contain whitespace, control, bidi or invisible formatting characters",
        ));
    }
    crate::rp::reject_reinterpreted_url_chars("redirect location", location).map_err(err)?;
    Ok(())
}

#[pymethods]
impl Response {
    #[new]
    #[pyo3(signature = (status, headers = None, body = None))]
    fn new(
        status: u16,
        headers: Option<Vec<(String, String)>>,
        body: Option<&[u8]>,
    ) -> PyResult<Self> {
        let headers = headers.unwrap_or_default();
        for (k, v) in &headers {
            check_response_header(k, v)?;
        }
        Ok(Self {
            inner: gh::Response {
                status,
                headers,
                body: body.map(|b| b.to_vec()).unwrap_or_default(),
            },
        })
    }

    #[getter]
    fn status(&self) -> u16 {
        self.inner.status
    }
    #[setter]
    fn set_status(&mut self, v: u16) {
        self.inner.status = v;
    }
    #[getter]
    fn headers(&self) -> Vec<(String, String)> {
        self.inner.headers.clone()
    }
    #[setter]
    fn set_headers(&mut self, v: Vec<(String, String)>) -> PyResult<()> {
        for (k, val) in &v {
            check_response_header(k, val)?;
        }
        self.inner.headers = v;
        Ok(())
    }
    #[getter]
    fn body<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.body)
    }
    #[setter]
    fn set_body(&mut self, v: &[u8]) {
        self.inner.body = v.to_vec();
    }

    /// Body decoded as UTF-8 (lossy).
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.inner.body).into_owned()
    }

    /// First value of header `name` (case-insensitive), if any.
    fn header(&self, name: &str) -> Option<String> {
        self.inner
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }

    /// Return a copy with an extra header appended. Raises `BadRequestError`
    /// for an empty or non-token name or a control character in the value.
    fn with_header(&self, name: String, value: String) -> PyResult<Self> {
        check_response_header(&name, &value)?;
        Ok(Self::wrap(self.inner.clone().with_header(name, value)))
    }
    /// Return a copy with the body replaced.
    fn with_body(&self, body: &[u8]) -> Self {
        Self::wrap(self.inner.clone().with_body(body.to_vec()))
    }

    /// 302 redirect to `location`. Raises `BadRequestError` if it contains
    /// whitespace, control, bidi or invisible formatting characters; no
    /// scheme or host policy is applied.
    #[staticmethod]
    fn redirect(location: String) -> PyResult<Self> {
        check_location(&location)?;
        Ok(Self::wrap(gh::Response::redirect(location)))
    }
    /// A `text/html` response.
    #[staticmethod]
    fn html(body: String) -> Self {
        Self::wrap(gh::Response::html(body))
    }
    /// An `application/json` response from any JSON-serializable value.
    #[staticmethod]
    #[pyo3(signature = (value, status = 200))]
    fn json(value: &Bound<'_, PyAny>, status: u16) -> PyResult<Self> {
        let v: serde_json::Value = from_py(value)?;
        gh::Response::json_status(status, &v)
            .map(Self::wrap)
            .map_err(err)
    }
    /// A plain-text response.
    #[staticmethod]
    #[pyo3(signature = (status, body))]
    fn text_response(status: u16, body: String) -> Self {
        Self::wrap(gh::Response::text(status, body))
    }

    fn __repr__(&self) -> String {
        format!(
            "Response(status={}, headers={:?}, body=<{} bytes>)",
            self.inner.status,
            self.inner.headers,
            self.inner.body.len()
        )
    }
}

// ---------------------------------------------------------------------------
// HttpFetchResponse
// ---------------------------------------------------------------------------

/// Lower-case header names (ASCII), keeping order and repeats.
fn lower_names(headers: Vec<(String, String)>) -> Vec<(String, String)> {
    headers
        .into_iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v))
        .collect()
}

/// The result of an outbound fetch made through an `HttpClient`.
#[pyclass(
    module = "pygrindvakt.http",
    name = "HttpFetchResponse",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct HttpFetchResponse {
    pub inner: RsFetch,
}

#[pymethods]
impl HttpFetchResponse {
    #[new]
    #[pyo3(signature = (status, body, content_type = None, headers = None))]
    fn new(
        status: u16,
        body: &[u8],
        content_type: Option<String>,
        headers: Option<Vec<(String, String)>>,
    ) -> Self {
        Self {
            inner: RsFetch {
                status,
                body: body.to_vec(),
                content_type,
                headers: lower_names(headers.unwrap_or_default()),
            },
        }
    }
    /// Response headers as `(name, value)` pairs: names lower-cased, order
    /// and repeated headers preserved. Empty when the client reports none.
    #[getter]
    fn headers(&self) -> Vec<(String, String)> {
        self.inner.headers.clone()
    }
    #[getter]
    fn status(&self) -> u16 {
        self.inner.status
    }
    #[getter]
    fn body<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.body)
    }
    #[getter]
    fn content_type(&self) -> Option<&str> {
        self.inner.content_type.as_deref()
    }
    fn text(&self) -> String {
        self.inner.text()
    }
    /// Parse the body as JSON into native Python objects.
    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let v: serde_json::Value = self.inner.json().map_err(err)?;
        to_py(py, &v)
    }
    fn __repr__(&self) -> String {
        format!(
            "HttpFetchResponse(status={}, content_type={:?}, headers={}, body=<{} bytes>)",
            self.inner.status,
            self.inner.content_type,
            self.inner.headers.len(),
            self.inner.body.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Transport failure capture
// ---------------------------------------------------------------------------

/// Why an outbound fetch failed before an HTTP response was obtained.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransportKind {
    Timeout,
    Connect,
    TooLarge,
    Body,
}

/// The original cause of a failed outbound fetch, kept so it can be chained
/// as `__cause__` (grindvakt itself only sees `Error::Internal(String)`).
pub enum TransportFailure {
    /// The Python `HttpClient` raised this exception.
    Python(PyErr),
    /// The built-in client failed.
    Reqwest { kind: TransportKind, detail: String },
}

/// Per-call slot for the latest [`TransportFailure`]. Every call to
/// [`extract_http_client`] creates a fresh slot, so concurrent and nested
/// calls never see each other's failures.
#[derive(Clone, Default)]
pub struct Failures(Arc<Mutex<Option<(String, TransportFailure)>>>);

impl Failures {
    /// `message` is the exact `Error::Internal` text returned to grindvakt
    /// for this failure; `err` only attributes the failure to an error that
    /// carries the same text.
    fn record(&self, message: String, f: TransportFailure) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some((message, f));
    }

    /// A later successful fetch supersedes an earlier failure (multi-fetch
    /// flows such as federation resolution may retry other endpoints).
    fn clear(&self) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    fn take(&self) -> Option<(String, TransportFailure)> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).take()
    }

    /// Map an error returned by a grindvakt call that used this call's
    /// client. If it is an `Internal` error and a transport failure was
    /// captured, raise `InternalError(code="transport")` (or
    /// `"response_too_large"`) chained to the original exception.
    pub fn err(&self, py: Python<'_>, e: RsError) -> PyErr {
        // Always consume the slot. Only attribute the failure to an Internal
        // error that is the one the failed fetch returned: a tolerated earlier
        // fetch failure must not be blamed for an unrelated Internal error.
        let captured = self.take();
        let RsError::Internal(emitted) = &e else {
            return err(e);
        };
        let Some((_, failure)) = captured.filter(|(m, _)| m == emitted) else {
            return err(e);
        };
        let msg = e.to_string();
        match failure {
            TransportFailure::Python(cause) => {
                let exc = with_code(py, InternalError::new_err(msg), "transport");
                exc.set_cause(py, Some(cause));
                exc
            }
            TransportFailure::Reqwest { kind, detail } => {
                let (code, cause): (&str, Option<PyErr>) = match kind {
                    TransportKind::Timeout => (
                        "transport",
                        Some(pyo3::exceptions::PyTimeoutError::new_err(detail)),
                    ),
                    TransportKind::Connect => (
                        "transport",
                        Some(pyo3::exceptions::PyConnectionError::new_err(detail)),
                    ),
                    TransportKind::Body => (
                        "transport",
                        Some(pyo3::exceptions::PyOSError::new_err(detail)),
                    ),
                    TransportKind::TooLarge => ("response_too_large", None),
                };
                let exc = with_code(py, InternalError::new_err(msg), code);
                if let Some(c) = cause {
                    exc.set_cause(py, Some(c));
                }
                exc
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Built-in reqwest client
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Limits {
    connect_timeout: u64,
    read_timeout: u64,
    request_timeout: u64,
    user_agent: String,
}

fn build_client(l: &Limits) -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(l.user_agent.clone())
        .connect_timeout(Duration::from_secs(l.connect_timeout))
        .read_timeout(Duration::from_secs(l.read_timeout))
        .timeout(Duration::from_secs(l.request_timeout))
        // Never follow redirects: a 307/308 would re-send token-endpoint form
        // bodies (client_secret, authorization code) cross-origin. Call sites
        // treat the resulting 3xx status as an error.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build reqwest client")
}

/// reqwest-backed `HttpClient`. The pool is keyed by PID and rebuilt after
/// `fork`, since inherited connections are dead in the child.
pub struct ReqwestHttpClient {
    inner: RwLock<(u32, reqwest::Client)>,
    limits: Limits,
    max_response_bytes: usize,
}

impl ReqwestHttpClient {
    fn new(limits: Limits, max_response_bytes: usize) -> Self {
        let client = build_client(&limits);
        Self {
            inner: RwLock::new((std::process::id(), client)),
            limits,
            max_response_bytes,
        }
    }

    fn client(&self) -> reqwest::Client {
        let pid = std::process::id();
        if let Ok(g) = self.inner.read() {
            if g.0 == pid {
                return g.1.clone();
            }
        }
        let fresh = build_client(&self.limits);
        *self.inner.write().unwrap_or_else(|e| e.into_inner()) = (pid, fresh.clone());
        fresh
    }
}

struct RawFailure {
    kind: TransportKind,
    detail: String,
}

fn send_failure(method: &str, url: &str, e: &reqwest::Error) -> RawFailure {
    let kind = if e.is_timeout() {
        TransportKind::Timeout
    } else if e.is_connect() {
        TransportKind::Connect
    } else {
        TransportKind::Body
    };
    RawFailure {
        kind,
        detail: format!("{method} {url}: {e}"),
    }
}

async fn into_fetch(
    method: &str,
    url: &str,
    mut resp: reqwest::Response,
    max: usize,
) -> Result<RsFetch, RawFailure> {
    let too_large = || RawFailure {
        kind: TransportKind::TooLarge,
        detail: format!("{method} {url}: outbound response exceeds {max} byte limit"),
    };
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    // Lower-cased names, in order, repeated headers kept; non-UTF-8 values
    // are skipped.
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_ascii_lowercase(), v.to_string()))
        })
        .collect();
    if resp.content_length().is_some_and(|l| l > max as u64) {
        return Err(too_large());
    }
    // Content-Length is optional and cannot be trusted on its own: stream the
    // body and check before every extension.
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| {
        let mut f = send_failure(method, url, &e);
        f.detail = format!("{method} {url}: reading body: {e}");
        f
    })? {
        let new_len = body
            .len()
            .checked_add(chunk.len())
            .filter(|l| *l <= max)
            .ok_or_else(too_large)?;
        body.reserve(new_len - body.len());
        body.extend_from_slice(&chunk);
    }
    Ok(RsFetch {
        status,
        body,
        content_type,
        headers,
    })
}

impl ReqwestHttpClient {
    async fn get_raw(
        &self,
        url: &str,
        headers: reqwest::header::HeaderMap,
    ) -> Result<RsFetch, RawFailure> {
        let resp = self
            .client()
            .get(url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| send_failure("GET", url, &e))?;
        into_fetch("GET", url, resp, self.max_response_bytes).await
    }

    async fn post_form_raw(
        &self,
        url: &str,
        form: &[(String, String)],
        headers: &reqwest::header::HeaderMap,
    ) -> Result<RsFetch, RawFailure> {
        let mut req = self.client().post(url).form(form);
        for (k, v) in headers {
            req = req.header(k, v.clone());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| send_failure("POST", url, &e))?;
        into_fetch("POST", url, resp, self.max_response_bytes).await
    }

    /// POST an already-serialized JSON body. The caller supplies the
    /// `Content-Type` in `headers`. Serialization is by hand: the binding's
    /// reqwest has no `json` feature.
    async fn post_json_raw(
        &self,
        url: &str,
        body: Vec<u8>,
        headers: reqwest::header::HeaderMap,
    ) -> Result<RsFetch, RawFailure> {
        let resp = self
            .client()
            .post(url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|e| send_failure("POST", url, &e))?;
        into_fetch("POST", url, resp, self.max_response_bytes).await
    }
}

/// Per-call view of the built-in client that records why a fetch failed (see
/// [`Failures`]). Cheap: one `Arc` clone and one fresh slot per call.
struct ReqwestCall {
    client: Arc<ReqwestHttpClient>,
    failures: Failures,
}

impl ReqwestCall {
    fn finish(&self, r: Result<RsFetch, RawFailure>) -> grindvakt::Result<RsFetch> {
        match r {
            Ok(f) => {
                self.failures.clear();
                Ok(f)
            }
            Err(f) => {
                let msg = f.detail.clone();
                self.failures.record(
                    msg.clone(),
                    TransportFailure::Reqwest {
                        kind: f.kind,
                        detail: f.detail,
                    },
                );
                Err(RsError::Internal(msg))
            }
        }
    }
}

/// Validate caller-supplied header pairs; a bad name or value is a
/// `BadRequest`, never a panic.
fn header_map(headers: &[(String, String)]) -> grindvakt::Result<reqwest::header::HeaderMap> {
    use reqwest::header::{HeaderName, HeaderValue};
    let mut map = reqwest::header::HeaderMap::new();
    for (k, v) in headers {
        let name = HeaderName::from_bytes(k.as_bytes())
            .map_err(|_| RsError::BadRequest(format!("invalid HTTP header name: {k:?}")))?;
        let mut value = HeaderValue::from_str(v)
            .map_err(|_| RsError::BadRequest(format!("invalid HTTP header value for {k:?}")))?;
        // Keep credentials out of reqwest's Debug output and HPACK indexes.
        if name == reqwest::header::AUTHORIZATION || name == reqwest::header::COOKIE {
            value.set_sensitive(true);
        }
        map.append(name, value);
    }
    // The client frames the request and addresses it from `url`. A caller
    // `Content-Length: 0` would silently drop a request body (a token request's
    // `client_secret` and code), and `Host` would misdirect the request at the
    // destination, so none of these may be supplied.
    use reqwest::header::{
        CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, EXPECT, HOST, TRANSFER_ENCODING,
    };
    if [
        CONTENT_LENGTH,
        TRANSFER_ENCODING,
        HOST,
        CONNECTION,
        EXPECT,
        CONTENT_ENCODING,
    ]
    .iter()
    .any(|n| map.contains_key(n))
    {
        return Err(RsError::BadRequest(
            "Content-Length, Transfer-Encoding, Host, Connection, Expect and \
             Content-Encoding are set by the client and cannot be supplied"
                .into(),
        ));
    }
    Ok(map)
}

/// RFC 9110 `token`: one or more visible ASCII characters other than
/// delimiters (so no spaces, commas, quotes, slashes or other separators).
fn is_http_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Whether a `Content-Type` value's media type (parameters ignored,
/// case-insensitive) is `application/json` or `application/*+json`, with a
/// subtype that is a valid RFC 9110 token.
fn is_json_media_type(value: &str) -> bool {
    let essence = value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match essence.strip_prefix("application/") {
        Some("json") => true,
        Some(sub) => sub.len() > "+json".len() && sub.ends_with("+json") && is_http_token(sub),
        None => false,
    }
}

/// Headers for a JSON POST with exactly one `Content-Type`: a caller-supplied
/// JSON media type is kept, any other is a `BadRequest`, none gets
/// `application/json`.
fn json_post_headers(
    headers: &[(String, String)],
) -> grindvakt::Result<reqwest::header::HeaderMap> {
    use reqwest::header::{HeaderValue, CONTENT_TYPE};
    let mut map = header_map(headers)?;
    let mut types = map.get_all(CONTENT_TYPE).iter();
    match (types.next(), types.next()) {
        (None, _) => {
            map.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        }
        (Some(v), None) => {
            if !v.to_str().map(is_json_media_type).unwrap_or(false) {
                return Err(RsError::BadRequest(
                    "post_json requires a JSON Content-Type (application/json or \
                     application/*+json)"
                        .into(),
                ));
            }
        }
        (Some(_), Some(_)) => {
            return Err(RsError::BadRequest(
                "post_json: more than one Content-Type header supplied".into(),
            ));
        }
    }
    Ok(map)
}

#[async_trait]
impl HttpClient for ReqwestCall {
    async fn get(&self, url: &str) -> grindvakt::Result<RsFetch> {
        self.finish(
            self.client
                .get_raw(url, reqwest::header::HeaderMap::new())
                .await,
        )
    }

    async fn get_with_headers(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> grindvakt::Result<RsFetch> {
        let map = header_map(headers)?;
        self.finish(self.client.get_raw(url, map).await)
    }

    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        headers: &[(String, String)],
    ) -> grindvakt::Result<RsFetch> {
        let map = header_map(headers)?;
        self.finish(self.client.post_form_raw(url, form, &map).await)
    }

    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
        headers: &[(String, String)],
    ) -> grindvakt::Result<RsFetch> {
        let map = json_post_headers(headers)?;
        let bytes = serde_json::to_vec(body)
            .map_err(|e| RsError::BadRequest(format!("post_json body is not serializable: {e}")))?;
        self.finish(self.client.post_json_raw(url, bytes, map).await)
    }
}

const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// The built-in outbound HTTP client (reqwest + rustls).
///
/// Never follows redirects, enforces connect/read/total timeouts and a
/// streaming response-size cap. Also exposes `get` / `post_form` / `post_json` so it
/// satisfies the Python `HttpClient` protocol itself.
///
/// Thread safety: the class is `frozen` and shares its state behind an `Arc`,
/// so one instance can be used from many threads; the GIL is released during
/// I/O (`runtime::block_on`), so concurrent calls run in parallel. `http=None`
/// selects a process-wide default instance with the same properties.
///
/// Fork safety: the connection pool is keyed by PID and rebuilt lazily in the
/// child after `fork`; inherited connections are never reused and the tokio
/// runtime is rebuilt per process (see ADR 0001). Forking while another
/// thread has a request in flight is not supported. Fork only while no
/// other thread is inside a pygrindvakt call (for example the gunicorn master
/// before worker threads start): an internal lock held by another thread at
/// fork time stays locked in the child and can deadlock it. Create a
/// `RedisStore` after fork; a `ReqwestClient` may be created before it.
#[pyclass(module = "pygrindvakt.http", name = "ReqwestClient", frozen)]
pub struct ReqwestClient {
    pub inner: Arc<ReqwestHttpClient>,
}

#[pymethods]
impl ReqwestClient {
    #[new]
    #[pyo3(signature = (connect_timeout = 10, read_timeout = 15, request_timeout = 30,
                        max_response_bytes = DEFAULT_MAX_RESPONSE_BYTES, user_agent = None))]
    fn new(
        connect_timeout: u64,
        read_timeout: u64,
        request_timeout: u64,
        max_response_bytes: usize,
        user_agent: Option<String>,
    ) -> PyResult<Self> {
        if connect_timeout == 0 || read_timeout == 0 || request_timeout == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "timeouts must be greater than zero",
            ));
        }
        if max_response_bytes == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "max_response_bytes must be greater than zero",
            ));
        }
        let limits = Limits {
            connect_timeout,
            read_timeout,
            request_timeout,
            user_agent: user_agent
                .unwrap_or_else(|| concat!("pygrindvakt/", env!("CARGO_PKG_VERSION")).to_string()),
        };
        Ok(Self {
            inner: Arc::new(ReqwestHttpClient::new(limits, max_response_bytes)),
        })
    }

    /// Issue a GET, optionally with request headers. Returns
    /// `(status, body, content_type)`. Redirects are never followed, so the
    /// headers (for example `Authorization`) are only ever sent to `url`.
    #[pyo3(signature = (url, headers = None))]
    fn get<'py>(
        &self,
        py: Python<'py>,
        url: String,
        headers: Option<Vec<(String, String)>>,
    ) -> PyResult<(u16, Bound<'py, PyBytes>, Option<String>)> {
        let failures = Failures::default();
        let client = ReqwestCall {
            client: self.inner.clone(),
            failures: failures.clone(),
        };
        let r = crate::runtime::block_on(py, async move {
            match headers {
                Some(h) => client.get_with_headers(&url, &h).await,
                None => client.get(&url).await,
            }
        })?
        .map_err(|e| failures.err(py, e))?;
        Ok((r.status, PyBytes::new(py, &r.body), r.content_type))
    }

    /// Issue a form-encoded POST. Returns `(status, body, content_type)`.
    #[pyo3(signature = (url, form, headers = None))]
    fn post_form<'py>(
        &self,
        py: Python<'py>,
        url: String,
        form: Vec<(String, String)>,
        headers: Option<Vec<(String, String)>>,
    ) -> PyResult<(u16, Bound<'py, PyBytes>, Option<String>)> {
        let failures = Failures::default();
        let client = ReqwestCall {
            client: self.inner.clone(),
            failures: failures.clone(),
        };
        let headers = headers.unwrap_or_default();
        let r =
            crate::runtime::block_on(
                py,
                async move { client.post_form(&url, &form, &headers).await },
            )?
            .map_err(|e| failures.err(py, e))?;
        Ok((r.status, PyBytes::new(py, &r.body), r.content_type))
    }

    /// Send a JSON body with a POST. Returns `(status, body, content_type)`.
    ///
    /// Lets you call a JSON API without another HTTP library, using this
    /// client's timeouts, response-size cap and TLS settings. `body` in the
    /// result is the raw response bytes: decode it yourself (`json.loads`).
    ///
    /// `body` is any JSON-compatible Python value (dict, list, tuple, str,
    /// int, float, bool, None), serialized compactly with dict order kept and
    /// integers exact. NaN / infinity raise `ValueError`, nesting deeper than
    /// 127 levels (`MAX_JSON_DEPTH` in `convert.rs`) raises `ValueError`, and a value that is not JSON-compatible raises
    /// `TypeError`; nothing is sent in those cases.
    ///
    /// Content-Type: `application/json` is set unless `headers` supplies one
    /// whose media type is `application/json` or `application/*+json`
    /// (parameters and case ignored), which is kept. Any other Content-Type
    /// raises `BadRequestError`. Redirects are never followed (including 307 /
    /// 308), so headers such as `Authorization` only go to `url`. An invalid
    /// header name or value raises `BadRequestError`, as does supplying
    /// `Content-Length`, `Transfer-Encoding`, `Host`, `Connection`, `Expect` or
    /// `Content-Encoding`
    /// (the client frames and addresses the request itself).
    #[pyo3(signature = (url, body, headers = None))]
    fn post_json<'py>(
        &self,
        py: Python<'py>,
        url: String,
        body: &Bound<'py, PyAny>,
        headers: Option<Vec<(String, String)>>,
    ) -> PyResult<(u16, Bound<'py, PyBytes>, Option<String>)> {
        // Convert while holding the GIL, before releasing it for I/O.
        let body: serde_json::Value = from_py(body)?;
        let failures = Failures::default();
        let client = ReqwestCall {
            client: self.inner.clone(),
            failures: failures.clone(),
        };
        let headers = headers.unwrap_or_default();
        let r =
            crate::runtime::block_on(
                py,
                async move { client.post_json(&url, &body, &headers).await },
            )?
            .map_err(|e| failures.err(py, e))?;
        Ok((r.status, PyBytes::new(py, &r.body), r.content_type))
    }

    fn __repr__(&self) -> String {
        format!(
            "ReqwestClient(connect_timeout={}, read_timeout={}, request_timeout={}, max_response_bytes={})",
            self.inner.limits.connect_timeout,
            self.inner.limits.read_timeout,
            self.inner.limits.request_timeout,
            self.inner.max_response_bytes
        )
    }
}

fn default_http_client() -> Arc<ReqwestHttpClient> {
    static DEFAULT: OnceLock<Arc<ReqwestHttpClient>> = OnceLock::new();
    DEFAULT
        .get_or_init(|| {
            Arc::new(ReqwestHttpClient::new(
                Limits {
                    connect_timeout: 10,
                    read_timeout: 15,
                    request_timeout: 30,
                    user_agent: concat!("pygrindvakt/", env!("CARGO_PKG_VERSION")).to_string(),
                },
                DEFAULT_MAX_RESPONSE_BYTES,
            ))
        })
        .clone()
}

// ---------------------------------------------------------------------------
// Python-implemented HttpClient adapter
// ---------------------------------------------------------------------------

/// Adapter that lets any Python object with `get` / `post_form` act as the
/// outbound client. The blocking Python call runs on the thread that is
/// already inside `runtime::block_on`, so it re-acquires the GIL briefly.
pub struct PyHttpClient {
    obj: Py<PyAny>,
    failures: Failures,
    headers_mode: HeadersMode,
}

/// How (whether) a Python client accepts request headers on GET, decided once
/// when the adapter is built.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HeadersMode {
    Unsupported,
    /// `get_with_headers(url, headers)`.
    GetWithHeaders,
    /// `get(url, headers=headers)`.
    GetKeyword,
}

/// `get` accepts `headers` by keyword (a positional-or-keyword or keyword-only
/// parameter) or `**kwargs`. Introspection failure
/// (for example a builtin without a signature) counts as unsupported.
fn get_accepts_headers(py: Python<'_>, obj: &Bound<'_, PyAny>) -> bool {
    let probe = || -> PyResult<bool> {
        let get = obj.getattr("get")?;
        let sig = py.import("inspect")?.call_method1("signature", (get,))?;
        let params = sig.getattr("parameters")?;
        let kinds = py.import("inspect")?.getattr("Parameter")?;
        // The adapter calls `get(url, headers=...)`, so `headers` must be
        // passable by keyword: a positional-only or `*headers` parameter
        // would raise TypeError on every call.
        if params.contains("headers")? {
            let kind = params.get_item("headers")?.getattr("kind")?;
            return Ok(kind.eq(&kinds.getattr("POSITIONAL_OR_KEYWORD")?)?
                || kind.eq(&kinds.getattr("KEYWORD_ONLY")?)?
                || kind.eq(&kinds.getattr("VAR_KEYWORD")?)?);
        }
        let var_kw = kinds.getattr("VAR_KEYWORD")?;
        for p in params.call_method0("values")?.try_iter()? {
            if p?.getattr("kind")?.eq(&var_kw)? {
                return Ok(true);
            }
        }
        Ok(false)
    };
    probe().unwrap_or(false)
}

fn headers_mode(py: Python<'_>, obj: &Bound<'_, PyAny>) -> HeadersMode {
    if obj
        .getattr("get_with_headers")
        .map(|a| a.is_callable())
        .unwrap_or(false)
    {
        HeadersMode::GetWithHeaders
    } else if get_accepts_headers(py, obj) {
        HeadersMode::GetKeyword
    } else {
        HeadersMode::Unsupported
    }
}

impl PyHttpClient {
    /// Log the adapter failure (ADR 0002: fail closed, report via the
    /// unraisable hook), keep the original exception for `__cause__` chaining
    /// and return the opaque grindvakt error.
    fn fail(&self, py: Python<'_>, obj: &Bound<'_, PyAny>, what: &str, e: PyErr) -> RsError {
        let msg = format!("python http client: {e}");
        log_unraisable(py, e.clone_ref(py), obj, what);
        self.failures
            .record(msg.clone(), TransportFailure::Python(e));
        RsError::Internal(msg)
    }

    fn ok(&self, f: RsFetch) -> RsFetch {
        self.failures.clear();
        f
    }
}

fn extract_fetch(r: &Bound<'_, PyAny>) -> PyResult<RsFetch> {
    if let Ok(f) = r.extract::<HttpFetchResponse>() {
        return Ok(f.inner);
    }
    let shape_err = |e: PyErr| {
        internal_err(format!(
            "HttpClient method must return (status: int, body: bytes, content_type: str | None \
             [, headers: list[tuple[str, str]] | None]) or an HttpFetchResponse: {e}"
        ))
    };
    // A 4-tuple carries response headers; a 3-tuple does not.
    let is_four = r.cast::<pyo3::types::PyTuple>().is_ok_and(|t| t.len() == 4);
    type Headers = Vec<(String, String)>;
    type Four = (u16, Vec<u8>, Option<String>, Option<Headers>);
    let (status, body, content_type, headers) = if is_four {
        let (s, b, c, h): Four = r.extract().map_err(shape_err)?;
        (s, b, c, h.unwrap_or_default())
    } else {
        let (s, b, c): (u16, Vec<u8>, Option<String>) = r.extract().map_err(shape_err)?;
        (s, b, c, Headers::new())
    };
    Ok(RsFetch {
        status,
        body,
        content_type,
        headers: lower_names(headers),
    })
}

#[async_trait]
impl HttpClient for PyHttpClient {
    async fn get(&self, url: &str) -> grindvakt::Result<RsFetch> {
        Python::attach(|py| {
            let obj = self.obj.bind(py);
            obj.call_method1("get", (url,))
                .and_then(|r| extract_fetch(&r))
                .map(|f| self.ok(f))
                .map_err(|e| self.fail(py, obj, "HttpClient.get", e))
        })
    }

    async fn get_with_headers(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> grindvakt::Result<RsFetch> {
        Python::attach(|py| {
            let obj = self.obj.bind(py);
            let (what, result) = match self.headers_mode {
                HeadersMode::Unsupported => {
                    return Err(RsError::Config(
                        "this HttpClient does not support request headers on GET: its `get` \
                         must accept a `headers` parameter (or **kwargs), or it must provide \
                         `get_with_headers(url, headers)`"
                            .into(),
                    ))
                }
                HeadersMode::GetWithHeaders => (
                    "HttpClient.get_with_headers",
                    obj.call_method1("get_with_headers", (url, headers.to_vec())),
                ),
                HeadersMode::GetKeyword => {
                    let kwargs = pyo3::types::PyDict::new(py);
                    let call = kwargs
                        .set_item("headers", headers.to_vec())
                        .and_then(|_| obj.call_method("get", (url,), Some(&kwargs)));
                    ("HttpClient.get", call)
                }
            };
            result
                .and_then(|r| extract_fetch(&r))
                .map(|f| self.ok(f))
                .map_err(|e| self.fail(py, obj, what, e))
        })
    }

    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        headers: &[(String, String)],
    ) -> grindvakt::Result<RsFetch> {
        Python::attach(|py| {
            let obj = self.obj.bind(py);
            obj.call_method1("post_form", (url, form.to_vec(), headers.to_vec()))
                .and_then(|r| extract_fetch(&r))
                .map(|f| self.ok(f))
                .map_err(|e| self.fail(py, obj, "HttpClient.post_form", e))
        })
    }

    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
        headers: &[(String, String)],
    ) -> grindvakt::Result<RsFetch> {
        Python::attach(|py| {
            let obj = self.obj.bind(py);
            if !obj
                .getattr("post_json")
                .map(|a| a.is_callable())
                .unwrap_or(false)
            {
                return Err(RsError::Config(
                    "this HttpClient does not support post_json: it must provide \
                     `post_json(url, body, headers)`"
                        .into(),
                ));
            }
            to_py(py, body)
                .and_then(|b| obj.call_method1("post_json", (url, b, headers.to_vec())))
                .and_then(|r| extract_fetch(&r))
                .map(|f| self.ok(f))
                .map_err(|e| self.fail(py, obj, "HttpClient.post_json", e))
        })
    }
}

/// Resolve the `http` argument of networked functions: `None` -> the shared
/// built-in client, a `ReqwestClient` -> its inner client, anything else ->
/// a Python protocol adapter (validated to have `get` and `post_form`).
///
/// Returns the client together with this call's [`Failures`] slot; pass failed
/// results through `Failures::err` so transport causes are chained.
pub fn extract_http_client(
    obj: Option<&Bound<'_, PyAny>>,
) -> PyResult<(Arc<dyn HttpClient>, Failures)> {
    let failures = Failures::default();
    let reqwest_call = |client: Arc<ReqwestHttpClient>| -> Arc<dyn HttpClient> {
        Arc::new(ReqwestCall {
            client,
            failures: failures.clone(),
        })
    };
    let client = match obj {
        None => reqwest_call(default_http_client()),
        Some(o) if o.is_none() => reqwest_call(default_http_client()),
        Some(o) => {
            if let Ok(h) = o.cast::<ReqwestClient>() {
                reqwest_call(h.get().inner.clone())
            } else {
                require_methods(o, &["get", "post_form"], "HttpClient")?;
                Arc::new(PyHttpClient {
                    obj: o.clone().unbind(),
                    failures: failures.clone(),
                    headers_mode: headers_mode(o.py(), o),
                })
            }
        }
    };
    Ok((client, failures))
}

/// Whether `client` can send request headers on GET, as
/// `rp.fetch_userinfo(method="GET")` needs, decided with the same test the
/// networked functions use but WITHOUT performing any request. `None` (the
/// built-in client) and a `ReqwestClient` are `True`. Any other object is
/// `True` only if it has callable `get` and `post_form` and either a callable
/// `get_with_headers` or a `get` taking `headers` by keyword (or `**kwargs`).
/// Never raises: an object of any other shape gives `False`. Lets an
/// application fail at startup instead of on the first userinfo call.
#[pyfunction]
#[pyo3(signature = (client))]
fn supports_get_with_headers(client: Option<&Bound<'_, PyAny>>) -> bool {
    let Some(o) = client.filter(|o| !o.is_none()) else {
        return true;
    };
    if o.cast::<ReqwestClient>().is_ok() {
        return true;
    }
    require_methods(o, &["get", "post_form"], "HttpClient").is_ok()
        && headers_mode(o.py(), o) != HeadersMode::Unsupported
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "http")?;
    m.add_class::<HttpRequestData>()?;
    m.add_class::<Response>()?;
    m.add_class::<HttpFetchResponse>()?;
    m.add_class::<ReqwestClient>()?;
    m.add_function(wrap_pyfunction!(supports_get_with_headers, &m)?)?;
    Ok(())
}
