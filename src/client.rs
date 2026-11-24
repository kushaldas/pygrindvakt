//! Bindings for `grindvakt::client` - registered relying parties and the
//! `ClientStore` protocol (built-in in-memory store or any Python object with
//! `get(client_id)`, `put(client)` and optionally `put_with_ttl(client, ttl)`).

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyModule;

use grindvakt::client as gc;
use grindvakt::client::ClientStore;
use grindvakt::jose_rs::jwk::JwkSet;

use crate::convert::{from_py, log_unraisable, new_submodule, require_methods, to_py};

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

const CLIENT_FIELDS: &[&str] = &[
    "client_id",
    "client_secret",
    "redirect_uris",
    "response_types",
    "grant_types",
    "token_endpoint_auth_method",
    "jwks",
    "scope",
    "subject_type",
    "client_name",
];

/// A registered relying party.
///
/// Construct with keyword arguments (unknown keywords are rejected, so a typo
/// such as `redirect_uri=` cannot silently produce an unusable client), or via
/// `Client.from_dict(...)`.
#[pyclass(module = "pygrindvakt.client", name = "Client", frozen, from_py_object)]
#[derive(Clone)]
pub struct Client {
    pub inner: gc::Client,
}

impl Client {
    pub fn wrap(inner: gc::Client) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl Client {
    #[new]
    #[pyo3(signature = (client_id, *, client_secret = None, redirect_uris = None,
                        response_types = None, grant_types = None,
                        token_endpoint_auth_method = None, jwks = None, scope = None,
                        subject_type = None, client_name = None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        client_id: String,
        client_secret: Option<String>,
        redirect_uris: Option<Vec<String>>,
        response_types: Option<Vec<String>>,
        grant_types: Option<Vec<String>>,
        token_endpoint_auth_method: Option<String>,
        jwks: Option<&Bound<'_, PyAny>>,
        scope: Option<String>,
        subject_type: Option<String>,
        client_name: Option<String>,
    ) -> PyResult<Self> {
        let jwks: Option<JwkSet> = match jwks {
            Some(j) if !j.is_none() => Some(from_py(j)?),
            _ => None,
        };
        Ok(Self {
            inner: gc::Client {
                client_id,
                client_secret,
                redirect_uris: redirect_uris.unwrap_or_default(),
                response_types: response_types.unwrap_or_else(|| vec!["code".into()]),
                grant_types: grant_types.unwrap_or_else(|| vec!["authorization_code".into()]),
                token_endpoint_auth_method: token_endpoint_auth_method
                    .unwrap_or_else(|| gc::AUTH_CLIENT_SECRET_BASIC.to_string()),
                jwks,
                scope,
                subject_type: subject_type.unwrap_or_else(|| "public".into()),
                client_name,
                response_policy: Default::default(),
            },
        })
    }

    /// Build from a dict (the same shape as `to_dict()` / a JSON client
    /// registration). Unknown keys raise `ValueError`.
    #[staticmethod]
    fn from_dict(d: &Bound<'_, PyAny>) -> PyResult<Self> {
        let v: serde_json::Value = from_py(d)?;
        let obj = v
            .as_object()
            .ok_or_else(|| PyValueError::new_err("Client.from_dict expects a dict"))?;
        let unknown: Vec<&String> = obj
            .keys()
            .filter(|k| !CLIENT_FIELDS.contains(&k.as_str()))
            .collect();
        if !unknown.is_empty() {
            return Err(PyValueError::new_err(format!(
                "unknown Client field(s): {}",
                unknown
                    .iter()
                    .map(|s| format!("{s:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        let inner: gc::Client = serde_json::from_value(v)
            .map_err(|e| PyValueError::new_err(format!("invalid Client: {e}")))?;
        Ok(Self { inner })
    }

    /// The client as a dict.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner)
    }

    /// Unpadded base64url SHA-256 of the registration snapshot. Pass it as
    /// `AuthCodePayload.registration_digest` when sealing codes yourself.
    fn registration_fingerprint(&self) -> PyResult<String> {
        self.inner
            .registration_fingerprint()
            .map_err(|e| PyValueError::new_err(format!("cannot fingerprint Client: {e}")))
    }

    #[getter]
    fn client_id(&self) -> &str {
        &self.inner.client_id
    }
    #[getter]
    fn client_secret(&self) -> Option<&str> {
        self.inner.client_secret.as_deref()
    }
    #[getter]
    fn redirect_uris(&self) -> Vec<String> {
        self.inner.redirect_uris.clone()
    }
    #[getter]
    fn response_types(&self) -> Vec<String> {
        self.inner.response_types.clone()
    }
    #[getter]
    fn grant_types(&self) -> Vec<String> {
        self.inner.grant_types.clone()
    }
    #[getter]
    fn token_endpoint_auth_method(&self) -> &str {
        &self.inner.token_endpoint_auth_method
    }
    /// The client's JWKS (for `private_key_jwt` / request objects) as a dict.
    #[getter]
    fn jwks<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        match &self.inner.jwks {
            Some(j) => Ok(Some(to_py(py, j)?)),
            None => Ok(None),
        }
    }
    #[getter]
    fn scope(&self) -> Option<&str> {
        self.inner.scope.as_deref()
    }
    #[getter]
    fn subject_type(&self) -> &str {
        &self.inner.subject_type
    }
    #[getter]
    fn client_name(&self) -> Option<&str> {
        self.inner.client_name.as_deref()
    }

    /// Whether `uri` exactly matches a registered redirect URI.
    fn allows_redirect(&self, uri: &str) -> bool {
        self.inner.allows_redirect(uri)
    }
    /// Whether the client is allowed the given response type.
    fn allows_response_type(&self, rt: &str) -> bool {
        self.inner.allows_response_type(rt)
    }

    fn __repr__(&self) -> String {
        format!(
            "Client(client_id={:?}, token_endpoint_auth_method={:?}, redirect_uris={:?}, grant_types={:?})",
            self.inner.client_id,
            self.inner.token_endpoint_auth_method,
            self.inner.redirect_uris,
            self.inner.grant_types
        )
    }
}

/// Accept a `Client` instance or a dict wherever a client is expected.
pub fn client_from_py(obj: &Bound<'_, PyAny>) -> PyResult<gc::Client> {
    if let Ok(c) = obj.extract::<Client>() {
        return Ok(c.inner);
    }
    Ok(Client::from_dict(obj)?.inner)
}

// ---------------------------------------------------------------------------
// InMemoryClientStore
// ---------------------------------------------------------------------------

/// In-memory client store with optional per-entry TTL (used by federation
/// auto-registration). Process-local.
#[pyclass(module = "pygrindvakt.client", name = "InMemoryClientStore", frozen)]
pub struct InMemoryClientStore {
    pub inner: Arc<gc::InMemoryClientStore>,
}

#[pymethods]
impl InMemoryClientStore {
    /// Seed with static clients. Duplicate `client_id`s raise `ValueError`
    /// (grindvakt would otherwise silently keep the last one).
    #[new]
    #[pyo3(signature = (clients = None))]
    fn new(clients: Option<Vec<Bound<'_, PyAny>>>) -> PyResult<Self> {
        let mut seen = BTreeSet::new();
        let mut list = Vec::new();
        for c in clients.unwrap_or_default() {
            let c = client_from_py(&c)?;
            if !seen.insert(c.client_id.clone()) {
                return Err(PyValueError::new_err(format!(
                    "duplicate client_id {:?}",
                    c.client_id
                )));
            }
            list.push(c);
        }
        Ok(Self {
            inner: Arc::new(gc::InMemoryClientStore::with_clients(list)),
        })
    }

    /// Look up a client (expired TTL entries are removed on lookup).
    fn get(&self, py: Python<'_>, client_id: String) -> PyResult<Option<Client>> {
        let store = self.inner.clone();
        let r = crate::runtime::block_on(py, async move { store.get(&client_id).await })?;
        Ok(r.map(Client::wrap))
    }
    /// Insert or replace a client with no expiry.
    fn put(&self, py: Python<'_>, client: &Bound<'_, PyAny>) -> PyResult<()> {
        let c = client_from_py(client)?;
        let store = self.inner.clone();
        crate::runtime::block_on(py, async move { store.put(c).await })
    }
    /// Insert or replace a client that expires after `ttl_secs`.
    fn put_with_ttl(
        &self,
        py: Python<'_>,
        client: &Bound<'_, PyAny>,
        ttl_secs: u64,
    ) -> PyResult<()> {
        let c = client_from_py(client)?;
        let store = self.inner.clone();
        crate::runtime::block_on(py, async move { store.put_with_ttl(c, ttl_secs).await })
    }
    fn __repr__(&self) -> &'static str {
        "InMemoryClientStore()"
    }
}

// ---------------------------------------------------------------------------
// Python-implemented ClientStore adapter
// ---------------------------------------------------------------------------

/// Adapter over a Python object implementing the `ClientStore` protocol.
/// Fails closed: an exception in `get` means "unknown client".
pub struct PyClientStore {
    obj: Py<PyAny>,
}

fn opt_client_from_py(r: &Bound<'_, PyAny>) -> PyResult<Option<gc::Client>> {
    if r.is_none() {
        return Ok(None);
    }
    client_from_py(r).map(Some)
}

#[async_trait]
impl ClientStore for PyClientStore {
    async fn get(&self, client_id: &str) -> Option<gc::Client> {
        Python::attach(|py| {
            let obj = self.obj.bind(py);
            match obj
                .call_method1("get", (client_id,))
                .and_then(|r| opt_client_from_py(&r))
            {
                Ok(c) => c,
                Err(e) => {
                    log_unraisable(py, e, obj, "ClientStore.get");
                    None
                }
            }
        })
    }

    async fn put(&self, client: gc::Client) {
        Python::attach(|py| {
            let obj = self.obj.bind(py);
            let res = Py::new(py, Client::wrap(client))
                .and_then(|c| obj.call_method1("put", (c,)).map(|_| ()));
            if let Err(e) = res {
                log_unraisable(py, e, obj, "ClientStore.put");
            }
        })
    }

    async fn put_with_ttl(&self, client: gc::Client, ttl: u64) {
        // Mirror the Rust default: fall back to `put` when the object has no
        // `put_with_ttl`.
        let fallback = Python::attach(|py| {
            let obj = self.obj.bind(py);
            if !obj.hasattr("put_with_ttl").unwrap_or(false) {
                return Some(client.clone());
            }
            let res = Py::new(py, Client::wrap(client.clone()))
                .and_then(|c| obj.call_method1("put_with_ttl", (c, ttl)).map(|_| ()));
            if let Err(e) = res {
                log_unraisable(py, e, obj, "ClientStore.put_with_ttl");
            }
            None
        });
        if let Some(c) = fallback {
            self.put(c).await;
        }
    }
}

/// Resolve a `clients` argument into an `Arc<dyn ClientStore>`: the built-in
/// store shares its inner `Arc`; any other object must implement `get` and
/// `put`.
pub fn extract_client_store(obj: &Bound<'_, PyAny>) -> PyResult<Arc<dyn ClientStore>> {
    if let Ok(s) = obj.cast::<InMemoryClientStore>() {
        return Ok(s.get().inner.clone());
    }
    require_methods(obj, &["get", "put"], "ClientStore")?;
    Ok(Arc::new(PyClientStore {
        obj: obj.clone().unbind(),
    }))
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "client")?;
    m.add_class::<Client>()?;
    m.add_class::<InMemoryClientStore>()?;
    m.add("AUTH_NONE", gc::AUTH_NONE)?;
    m.add("AUTH_CLIENT_SECRET_BASIC", gc::AUTH_CLIENT_SECRET_BASIC)?;
    m.add("AUTH_CLIENT_SECRET_POST", gc::AUTH_CLIENT_SECRET_POST)?;
    m.add("AUTH_PRIVATE_KEY_JWT", gc::AUTH_PRIVATE_KEY_JWT)?;
    Ok(())
}
