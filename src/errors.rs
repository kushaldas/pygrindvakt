//! Exception hierarchy for pygrindvakt.
//!
//! ```text
//! GrindvaktError(Exception)            status_hint: int, code: str (class attributes;
//!                                      `code` is overridden per instance when known),
//!                                      auth_failure, retryable: bool, log_summary
//! ├── BadRequestError (400)            grindvakt::Error::BadRequest, and argument
//! │                                    validation; also derives from ValueError
//! ├── AuthnError (401)                 grindvakt::Error::Authn, and
//! │                                    Error::UpstreamHttp from token/UserInfo
//! ├── StateError (500)                 grindvakt::Error::State
//! ├── ConfigError (500)                grindvakt::Error::Config, and RP/metadata
//! │                                    configuration faults; also a ValueError
//! ├── CryptoError (500)                grindvakt::Error::Crypto
//! ├── AttributeMappingError (500)      grindvakt::Error::Attribute
//! ├── JoseError (500)                  grindvakt::Error::Jose
//! │   └── UnknownKeyError (401)        raised by rp.JwksCache (no upstream variant)
//! ├── JsonError (500)                  grindvakt::Error::Json
//! ├── InternalError (500)              grindvakt::Error::Internal, and
//! │                                    other Error::UpstreamHttp (JWKS, discovery,
//! │                                    federation fetches)
//! ├── NoBoundEndpointError (404)       grindvakt::Error::NoBoundEndpoint
//! ├── UnknownModuleError (404)         grindvakt::Error::UnknownModule
//! ├── OAuthError                       grindvakt::OAuthError (defined in Python,
//! │                                    see python/pygrindvakt/errors.py)
//! └── DpopError                        grindvakt::DpopError
//!     ├── DpopInvalidError
//!     ├── DpopReplayError
//!     ├── DpopNonceRequiredError
//!     └── DpopServerError
//! ```
//!
//! `BadRequestError` and `ConfigError` have two bases (`GrindvaktError`,
//! `ValueError`), which `create_exception!` cannot express, so they are built
//! with `type(...)` and kept in `BAD_REQUEST` / `CONFIG`; `bad_request_err`
//! and `config_err` raise them.
//!
//! `OAuthError` needs data attributes *and* methods (`to_response()`,
//! `to_redirect()`), and `#[pyclass(extends = PyException)]` is not available
//! under the abi3 limited API below Python 3.12. It is therefore a plain Python
//! class subclassing the native `GrindvaktError`; Rust raises it through a
//! lazily resolved type handle and the rendering is done by the two native
//! helper functions at the bottom of this file.

use std::fmt::Display;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyDict, PyType};
use pyo3::{create_exception, exceptions::PyException};

use grindvakt::OAuthErrorCode;
use grindvakt::{DpopError as RsDpopError, Error as RsError, OAuthError as RsOAuthError};

create_exception!(
    pygrindvakt,
    GrindvaktError,
    PyException,
    "Base class for all pygrindvakt errors."
);
create_exception!(
    pygrindvakt,
    AuthnError,
    GrindvaktError,
    "Authentication failed somewhere in the flow."
);
create_exception!(
    pygrindvakt,
    StateError,
    GrindvaktError,
    "Flow state could not be sealed/unsealed."
);
create_exception!(
    pygrindvakt,
    CryptoError,
    GrindvaktError,
    "Cryptographic / key-material failure."
);
create_exception!(
    pygrindvakt,
    AttributeMappingError,
    GrindvaktError,
    "Attribute mapping failure."
);
create_exception!(
    pygrindvakt,
    JoseError,
    GrindvaktError,
    "JOSE (JWS/JWE/JWK) error."
);
create_exception!(
    pygrindvakt,
    UnknownKeyError,
    JoseError,
    "The token's `kid` names no key in the issuer's JWK Set, even after a refresh."
);
create_exception!(
    pygrindvakt,
    JsonError,
    GrindvaktError,
    "JSON (de)serialization error."
);
create_exception!(
    pygrindvakt,
    InternalError,
    GrindvaktError,
    "Any other internal error."
);
create_exception!(
    pygrindvakt,
    NoBoundEndpointError,
    GrindvaktError,
    "No endpoint bound to path."
);
create_exception!(
    pygrindvakt,
    UnknownModuleError,
    GrindvaktError,
    "Unknown module."
);

create_exception!(
    pygrindvakt,
    DpopError,
    GrindvaktError,
    "Base class for DPoP proof validation errors."
);
create_exception!(
    pygrindvakt,
    DpopInvalidError,
    DpopError,
    "The DPoP proof is malformed or fails validation."
);
create_exception!(
    pygrindvakt,
    DpopReplayError,
    DpopError,
    "The DPoP proof's jti was already seen."
);
create_exception!(
    pygrindvakt,
    DpopNonceRequiredError,
    DpopError,
    "A server nonce is required; challenge the client with `use_dpop_nonce`."
);
create_exception!(
    pygrindvakt,
    DpopServerError,
    DpopError,
    "The replay store failed; the proof could not be evaluated."
);

static BAD_REQUEST: PyOnceLock<Py<PyType>> = PyOnceLock::new();
static CONFIG: PyOnceLock<Py<PyType>> = PyOnceLock::new();

/// Build `name(GrindvaktError, ValueError)`. `code` and `status_hint` are set
/// in the class dict here, so they hold on every instance whether or not
/// `register` has run yet.
fn build_value_error_type(
    py: Python<'_>,
    name: &str,
    doc: &str,
    status: u16,
    code: &str,
) -> PyResult<Py<PyType>> {
    let dict = PyDict::new(py);
    dict.set_item("__module__", "pygrindvakt")?;
    dict.set_item("__doc__", doc)?;
    dict.set_item("status_hint", status)?;
    dict.set_item("code", code)?;
    let bases = (
        py.get_type::<GrindvaktError>(),
        py.get_type::<PyValueError>(),
    );
    let t = py
        .import("builtins")?
        .getattr("type")?
        .call1((name, bases, dict))?;
    Ok(t.cast_into::<PyType>().map_err(PyErr::from)?.unbind())
}

fn bad_request_type<'py>(py: Python<'py>) -> PyResult<&'py Bound<'py, PyType>> {
    BAD_REQUEST
        .get_or_try_init(py, || {
            build_value_error_type(
                py,
                "BadRequestError",
                "The request was malformed.",
                400,
                "bad_request",
            )
        })
        .map(|t| t.bind(py))
}

fn config_type<'py>(py: Python<'py>) -> PyResult<&'py Bound<'py, PyType>> {
    CONFIG
        .get_or_try_init(py, || {
            build_value_error_type(
                py,
                "ConfigError",
                "Configuration is invalid.",
                500,
                "config",
            )
        })
        .map(|t| t.bind(py))
}

fn raise_value_error_type(
    get: for<'py> fn(Python<'py>) -> PyResult<&'py Bound<'py, PyType>>,
    msg: String,
) -> PyErr {
    // `register` forces both types at import, so a failure to *build* one
    // fails the import loudly. The fallback below is only reachable when
    // instantiating an already-built type fails (e.g. out of memory); the
    // failure is chained as `__cause__` so it is not silent.
    Python::attach(|py| match get(py).and_then(|t| t.call1((msg.as_str(),))) {
        Ok(exc) => PyErr::from_value(exc),
        Err(cause) => {
            let fallback = PyValueError::new_err(msg);
            fallback.set_cause(py, Some(cause));
            fallback
        }
    })
}

/// Build a `BadRequestError` (also a `ValueError`) with a message. If the
/// type cannot be built, fall back to a plain `ValueError` with the same
/// message so the validation text is never hidden.
pub fn bad_request_err(msg: impl Into<String>) -> PyErr {
    raise_value_error_type(bad_request_type, msg.into())
}

/// Build a `ConfigError` (also a `ValueError`, status_hint 500) with a
/// message. Same fallback as `bad_request_err`.
pub fn config_err(msg: impl Into<String>) -> PyErr {
    raise_value_error_type(config_type, msg.into())
}

/// Like `err`, but a `BadRequest` becomes a `ConfigError`: for validators
/// that run on integrator-supplied configuration, not on request input.
pub fn config_from(e: RsError) -> PyErr {
    match e {
        RsError::BadRequest(m) => config_err(m),
        other => err(other),
    }
}

/// Codes of failures worth retrying (transient by nature).
///
/// `discovery_fetch_timeout` is raised by `rp.DiscoveryCache`.
/// `discovery_backoff` is deliberately NOT listed: its `retryable` follows the
/// stored cause (`with_code_retryable`), so a `with_code` call for it must not
/// be able to claim unconditional retryability.
const RETRYABLE_CODES: [&str; 3] = ["transport", "jwks_fetch_timeout", "discovery_fetch_timeout"];

/// Code rule for `retryable`: applies ONLY to codes the binding itself sets
/// (`with_code`); a `code` adopted from upstream OAuth text in `err()` must
/// never reach it. The status rule (upstream 5xx or 429) is core's
/// `UpstreamHttpError::is_retryable`.
fn is_retryable_code(code: &str) -> bool {
    RETRYABLE_CODES.contains(&code)
}

/// Best-effort setter for the per-instance attributes of a typed error.
///
/// Invariant: the typed exception is never replaced. Every attribute is
/// attempted independently, so one failure cannot leave later ones unset. A
/// failure is recorded and `finish` attaches a note (via `add_note`, Python
/// 3.11+, ignored where missing) describing it. Whatever could not be set
/// degrades to the class-level default, which is safe by default
/// (`auth_failure` False, `retryable` False): a failed override for a 503
/// therefore reads as `retryable` False. Setting an attribute on a plain
/// exception instance cannot realistically fail; this is defence in depth.
struct Attrs<'a, 'py> {
    py: Python<'py>,
    exc: &'a PyErr,
    failed: Vec<String>,
}

impl<'a, 'py> Attrs<'a, 'py> {
    fn new(py: Python<'py>, exc: &'a PyErr) -> Self {
        Self {
            py,
            exc,
            failed: Vec::new(),
        }
    }

    fn set<T: IntoPyObject<'py>>(&mut self, name: &str, v: T) {
        if let Err(err) = self.exc.value(self.py).setattr(name, v) {
            self.failed.push(format!("{name}: {err}"));
        }
    }

    fn set_opt<T: IntoPyObject<'py>>(&mut self, name: &str, v: Option<T>) {
        if let Some(v) = v {
            self.set(name, v);
        }
    }

    fn finish(self) {
        if self.failed.is_empty() {
            return;
        }
        let note = format!(
            "pygrindvakt: could not set error attribute(s), class defaults apply: {}",
            self.failed.join("; ")
        );
        // `add_note` exists on 3.11+ only; any failure here is ignored.
        let _ = self.exc.value(self.py).call_method1("add_note", (note,));
    }
}

/// Set the machine-readable `code` on a freshly built exception, overriding
/// the class-level default. Transient codes also set `retryable`. Always
/// returns `e` itself (see `Attrs`).
pub fn with_code(py: Python<'_>, e: PyErr, code: &str) -> PyErr {
    let mut attrs = Attrs::new(py, &e);
    attrs.set("code", code);
    if is_retryable_code(code) {
        attrs.set("retryable", true);
    }
    attrs.finish();
    e
}

/// Like `with_code`, but `retryable` is set explicitly instead of derived
/// from the code. For `discovery_backoff`, which inherits the `retryable` of
/// the stored failure it is chained to (that value was itself derived by
/// `err()`, so upstream text never reaches it).
pub fn with_code_retryable(py: Python<'_>, e: PyErr, code: &str, retryable: bool) -> PyErr {
    let mut attrs = Attrs::new(py, &e);
    attrs.set("code", code);
    attrs.set("retryable", retryable);
    attrs.finish();
    e
}

/// Map a `grindvakt::Error` onto the typed exception hierarchy.
///
/// Every exception carries a `code` (class default, overridden per instance
/// where a precise code is known). Upstream HTTP failures also expose the
/// sanitized `upstream_*` attributes.
pub fn err(e: RsError) -> PyErr {
    let msg = e.to_string();
    // Upstream HTTP failures (token, UserInfo, JWKS, discovery, federation
    // fetches) used to surface as `Authn` or `Internal`; keep that mapping.
    if let RsError::UpstreamHttp(u) = &e {
        let auth = e.is_auth_failure();
        let exc = if auth {
            AuthnError::new_err(msg)
        } else {
            InternalError::new_err(msg)
        };
        return Python::attach(|py| {
            // Only token/UserInfo failures adopt the upstream OAuth code;
            // metadata fetches (JWKS, discovery, federation) are `upstream_http`.
            let code = match (&u.error, auth) {
                (Some(c), true) => Some(c.clone()),
                (_, false) => Some("upstream_http".to_string()),
                (None, true) => None,
            };
            // `code` may be upstream-controlled text: derive retryable from status only.
            let retry = u.is_retryable();
            let mut attrs = Attrs::new(py, &exc);
            attrs.set_opt("code", code);
            attrs.set("auth_failure", auth);
            if retry {
                attrs.set("retryable", true);
            }
            attrs.set_opt("upstream_status", u.status);
            attrs.set_opt("upstream_error", u.error.clone());
            attrs.set_opt("upstream_error_description", u.error_description.clone());
            attrs.set_opt("upstream_body", u.body.clone());
            attrs.finish();
            exc
        });
    }
    match e {
        RsError::NoBoundEndpoint(_) => NoBoundEndpointError::new_err(msg),
        RsError::UnknownModule(_) => UnknownModuleError::new_err(msg),
        RsError::BadRequest(_) => bad_request_err(msg),
        RsError::Authn(_) => AuthnError::new_err(msg),
        RsError::UnmetAuthenticationRequirements => Python::attach(|py| {
            with_code(
                py,
                AuthnError::new_err(msg),
                "unmet_authentication_requirements",
            )
        }),
        RsError::State(_) => StateError::new_err(msg),
        RsError::Config(_) => config_err(msg),
        RsError::Crypto(_) => CryptoError::new_err(msg),
        RsError::Attribute(_) => AttributeMappingError::new_err(msg),
        RsError::Jose(_) => JoseError::new_err(msg),
        RsError::Json(_) => JsonError::new_err(msg),
        // `UpstreamHttp` is handled above; `Error` is `#[non_exhaustive]`, so
        // any future variant maps to the generic internal error.
        _ => InternalError::new_err(msg),
    }
}

/// Map a `grindvakt::DpopError` onto the DPoP exception subtree.
pub fn dpop_err(e: RsDpopError) -> PyErr {
    let msg = e.to_string();
    match e {
        RsDpopError::Invalid(_) => DpopInvalidError::new_err(msg),
        RsDpopError::Replay => DpopReplayError::new_err(msg),
        RsDpopError::NonceRequired => DpopNonceRequiredError::new_err(msg),
        RsDpopError::Server(_) => DpopServerError::new_err(msg),
    }
}

/// Generic helpers for errors that only carry a message.
pub fn crypto_err<E: Display>(e: E) -> PyErr {
    CryptoError::new_err(e.to_string())
}
pub fn internal_err<E: Display>(e: E) -> PyErr {
    InternalError::new_err(e.to_string())
}
pub fn jose_err<E: Display>(e: E) -> PyErr {
    JoseError::new_err(e.to_string())
}

// ---------------------------------------------------------------------------
// OAuthError (Python-defined, raised from Rust)
// ---------------------------------------------------------------------------

static OAUTH_ERROR: PyOnceLock<Py<PyType>> = PyOnceLock::new();

fn oauth_error_type<'py>(py: Python<'py>) -> PyResult<&'py Bound<'py, PyType>> {
    OAUTH_ERROR
        .get_or_try_init(py, || {
            py.import("pygrindvakt.errors")?
                .getattr("OAuthError")?
                .cast_into::<PyType>()
                .map(Bound::unbind)
                .map_err(PyErr::from)
        })
        .map(|t| t.bind(py))
}

/// Raise `pygrindvakt.OAuthError(code, description, state)` for a
/// `grindvakt::OAuthError`.
pub fn oauth_err(py: Python<'_>, e: &RsOAuthError) -> PyErr {
    match oauth_error_type(py)
        .and_then(|t| t.call1((e.code.as_str(), e.description.clone(), e.state.clone())))
    {
        Ok(exc) => PyErr::from_value(exc),
        // The package is broken (errors.py missing); surface that instead.
        Err(import_err) => import_err,
    }
}

// NOTE: `AuthorizationResponse.error_known` (core `grindvakt::callback`) is a
// SUPERSET of the codes accepted here; tests/test_rp.py locks that in. Do not
// widen this without core support.
pub fn parse_oauth_code(s: &str) -> PyResult<OAuthErrorCode> {
    s.parse::<OAuthErrorCode>()
        .map_err(|_| PyValueError::new_err(format!("unknown OAuth error code {s:?}")))
}

pub fn build_oauth_error(
    code: &str,
    description: Option<String>,
    state: Option<String>,
) -> PyResult<RsOAuthError> {
    Ok(RsOAuthError {
        code: parse_oauth_code(code)?,
        description,
        state,
    })
}

/// Render an OAuth error as a direct JSON response (token/userinfo endpoints).
/// Backs `OAuthError.to_response()`.
#[pyfunction]
#[pyo3(signature = (code, description = None, state = None))]
fn oauth_error_response(
    code: &str,
    description: Option<String>,
    state: Option<String>,
) -> PyResult<crate::http::Response> {
    Ok(crate::http::Response::wrap(
        build_oauth_error(code, description, state)?.to_response(),
    ))
}

/// Render an OAuth error as a redirect back to the client (authorization
/// endpoint). Backs `OAuthError.to_redirect(redirect_uri, response_mode)`.
#[pyfunction]
#[pyo3(signature = (code, redirect_uri, response_mode, description = None, state = None))]
fn oauth_error_redirect(
    code: &str,
    redirect_uri: &str,
    response_mode: &str,
    description: Option<String>,
    state: Option<String>,
) -> PyResult<crate::http::Response> {
    let fragment = match response_mode {
        "query" => false,
        "fragment" => true,
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unsupported response_mode: {other}"
            )))
        }
    };
    // Fail closed: the base is concatenated into `Location` verbatim, so it
    // must be a clean, fragment-free, userinfo-free URI (RFC 6749 4.1.2.1).
    // The caller is still responsible for the exact-match registration check.
    // Core's errors may quote the value, and truncate rather than omit it
    // (`display_safe`), so a long value's prefix survives. Never inspect or
    // forward the upstream text: every failure maps to one fixed message.
    crate::rp::check_redirect_uri(redirect_uri).map_err(|_| {
        bad_request_err("redirect_uri must be an absolute URI without a fragment (not echoed)")
    })?;
    Ok(crate::http::Response::wrap(
        build_oauth_error(code, description, state)?.to_redirect(redirect_uri, fragment),
    ))
}

/// HTTP status conventionally paired with an OAuth error code.
#[pyfunction]
fn oauth_error_http_status(code: &str) -> PyResult<u16> {
    Ok(parse_oauth_code(code)?.http_status())
}

/// Private helper behind `OAuthError.__str__`.
#[pyfunction]
#[pyo3(name = "escape_untrusted_text")]
fn escape_untrusted_text_py(s: &str, max_chars: usize) -> String {
    escape_untrusted_text(s, max_chars)
}

const LOG_CODE_MAX: usize = 64;
const LOG_MSG_MAX: usize = 512;

pub(crate) use grindvakt::is_invisible_format;

/// Escape untrusted text for logs and `str()`: control characters, anything
/// matching `is_invisible_format`, and backslash become `\n`, `\r`, `\t`,
/// `\\` or `\u{XXXX}`; the result is capped at `max` characters, ending with
/// `...` when cut. An escape sequence is never split. Shared by
/// `log_summary`, `OAuthError.__str__` and `error_description_safe`.
pub(crate) fn escape_untrusted_text(s: &str, max: usize) -> String {
    escape_untrusted(s, max, false)
}

/// Like `escape_untrusted_text`, but a single quote also becomes `\'` before
/// the cap is applied, so a value rendered inside single quotes stays within
/// `max` characters.
pub(crate) fn escape_untrusted_quoted(s: &str, max: usize) -> String {
    escape_untrusted(s, max, true)
}

fn escape_untrusted(s: &str, max: usize, escape_quote: bool) -> String {
    let mut out = String::new();
    let mut len = 0usize;
    // Length at which the cut happens, leaving room for the marker.
    let mut cut: Option<usize> = None;
    for c in s.chars() {
        let piece = match c {
            '\\' => "\\\\".to_string(),
            '\'' if escape_quote => "\\'".to_string(),
            '\n' => "\\n".to_string(),
            '\r' => "\\r".to_string(),
            '\t' => "\\t".to_string(),
            c if c.is_control() || is_invisible_format(c) => {
                format!("\\u{{{:04x}}}", c as u32)
            }
            c => c.to_string(),
        };
        let n = piece.chars().count();
        if cut.is_none() && len + n > max.saturating_sub(3) {
            cut = Some(out.len());
        }
        if len + n > max {
            out.truncate(cut.unwrap_or(out.len()));
            out.push_str("...");
            return out;
        }
        out.push_str(&piece);
        len += n;
    }
    out
}

/// Getter behind `GrindvaktError.log_summary`. Never raises: a missing or
/// non-string `code`, or a missing `status_hint`, falls back to `None`.
#[pyfunction]
fn log_summary(slf: &Bound<'_, PyAny>) -> String {
    let class = slf
        .get_type()
        .name()
        .map(|n| n.to_string())
        .unwrap_or_else(|_| "GrindvaktError".to_string());
    let class = escape_untrusted_text(&class, LOG_CODE_MAX);
    let code = match slf.getattr("code").and_then(|c| c.extract::<String>()) {
        Ok(c) => format!("'{}'", escape_untrusted_quoted(&c, LOG_CODE_MAX)),
        Err(_) => "None".to_string(),
    };
    let hint = match slf.getattr("status_hint").and_then(|h| h.extract::<i64>()) {
        Ok(h) => h.to_string(),
        Err(_) => "None".to_string(),
    };
    let msg = slf
        .str()
        .map(|m| m.to_string())
        .map(|m| escape_untrusted_text(&m, LOG_MSG_MAX))
        .unwrap_or_default();
    format!("{class}(code={code}, status_hint={hint}): {msg}")
}

/// Register exception types (and the OAuthError helpers) on the top-level module.
pub fn register(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    macro_rules! add {
        ($name:ident, $status:expr, $code:expr) => {{
            let t = py.get_type::<$name>();
            t.setattr("status_hint", $status)?;
            t.setattr("code", $code)?;
            m.add(stringify!($name), t)?;
        }};
    }
    add!(GrindvaktError, 500u16, "internal");
    m.add("BadRequestError", bad_request_type(py)?)?;
    add!(AuthnError, 401u16, "authn");
    py.get_type::<AuthnError>().setattr("auth_failure", true)?;
    add!(StateError, 500u16, "state");
    m.add("ConfigError", config_type(py)?)?;
    add!(CryptoError, 500u16, "crypto");
    add!(AttributeMappingError, 500u16, "attribute");
    add!(JoseError, 500u16, "jose");
    add!(UnknownKeyError, 401u16, "unknown_kid");
    add!(JsonError, 500u16, "json");
    add!(InternalError, 500u16, "internal");
    add!(NoBoundEndpointError, 404u16, "no_bound_endpoint");
    add!(UnknownModuleError, 404u16, "unknown_module");
    add!(DpopError, 400u16, "dpop");
    add!(DpopInvalidError, 400u16, "invalid_dpop_proof");
    add!(DpopReplayError, 400u16, "dpop_replay");
    add!(DpopNonceRequiredError, 400u16, "use_dpop_nonce");
    add!(DpopServerError, 500u16, "dpop_server");

    // Upstream HTTP details (sanitized by grindvakt); `None` unless the error
    // came from an upstream response. Inherited by every subclass.
    let base = py.get_type::<GrindvaktError>();
    for name in [
        "upstream_status",
        "upstream_error",
        "upstream_error_description",
        "upstream_body",
    ] {
        base.setattr(name, py.None())?;
    }
    base.setattr("auth_failure", false)?;
    base.setattr("retryable", false)?;
    let getter = wrap_pyfunction!(log_summary, m)?;
    let prop = py
        .import("builtins")?
        .getattr("property")?
        .call1((getter,))?;
    base.setattr("log_summary", prop)?;

    m.add_function(wrap_pyfunction!(oauth_error_response, m)?)?;
    m.add_function(wrap_pyfunction!(oauth_error_redirect, m)?)?;
    m.add_function(wrap_pyfunction!(oauth_error_http_status, m)?)?;
    m.add_function(wrap_pyfunction!(escape_untrusted_text_py, m)?)?;
    Ok(())
}
