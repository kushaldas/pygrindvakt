//! Bindings for `grindvakt::federation` - OpenID Federation 1.0 support.
//!
//! Entity statements (build + verify), trust-chain resolution by delegating to
//! a trust anchor's `federation_resolve_endpoint`, signed-JWKS fetching, the
//! collection (listing) endpoint used for OP discovery pages, and the
//! metadata-policy operators.
//!
//! JSON-shaped values (claims, JWKS, metadata, policies) cross the boundary as
//! native Python dicts / lists. Networked functions take an `http` client as
//! their first positional argument (`None` selects the built-in client) and
//! block the calling thread with the GIL released.

use std::collections::HashMap;

use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde_json::{Map, Value};

use grindvakt::federation as gf;
use grindvakt::jose_rs::jwk::JwkSet;
use grindvakt::jose_rs::jwt::Validation;

use crate::convert::{from_py, new_submodule, to_py};
use crate::errors::{err, with_code, AuthnError};
use crate::http::extract_http_client;
use crate::jwt::{drop_oct_keys, jwks_from_py, warn_if_publishing_oct};
use crate::keys::SigningKey;

// ---------------------------------------------------------------------------
// Symmetric-key guard (ADR 0006)
// ---------------------------------------------------------------------------

/// `jwt::drop_oct_keys` for federation key sets. Federation entities sign
/// with asymmetric keys; a symmetric key in a published or caller-supplied set
/// would let whoever can read it forge any statement it verifies.
fn drop_federation_oct_keys(py: Python<'_>, jwks: JwkSet) -> JwkSet {
    drop_oct_keys(
        py,
        jwks,
        "federation JWKS",
        "federation entities sign with asymmetric keys; symmetric keys cannot be published",
    )
}

/// Refuse a federation document whose JWS header `alg` is `HS256` / `HS384` /
/// `HS512` or `none`: entity statements and signed JWK Sets are never
/// MAC-signed or unsigned. Raises `AuthnError(code="symmetric_algorithm")`.
fn refuse_mac_or_none(py: Python<'_>, token: &str) -> PyResult<()> {
    let Ok(header) = grindvakt::jwt::peek_header(token) else {
        return Ok(());
    };
    let alg = header.alg.as_str();
    if ["HS256", "HS384", "HS512", "none"]
        .iter()
        .any(|a| alg.eq_ignore_ascii_case(a))
    {
        return Err(with_code(
            py,
            AuthnError::new_err(format!(
                "federation document signed with {alg}: entity statements are signed with \
                 asymmetric keys"
            )),
            "symmetric_algorithm",
        ));
    }
    Ok(())
}

/// `jwks_from_py` followed by the `oct` drop, for every verifier key set.
fn verifier_jwks(py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<JwkSet> {
    Ok(drop_federation_oct_keys(py, jwks_from_py(obj)?))
}

// ---------------------------------------------------------------------------
// EntityStatement
// ---------------------------------------------------------------------------

/// The decoded claims of an entity statement (entity configuration,
/// subordinate statement or resolve response).
///
/// `claims` is the full JSON object; the accessors read the standard
/// federation members from it.
#[pyclass(
    module = "pygrindvakt.federation",
    name = "EntityStatement",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct EntityStatement {
    pub inner: gf::EntityStatement,
}

impl EntityStatement {
    pub fn wrap(inner: gf::EntityStatement) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl EntityStatement {
    /// All claims of the statement as a dict.
    #[getter]
    fn claims<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner.claims)
    }
    /// The `iss` claim, if present.
    fn iss(&self) -> Option<&str> {
        self.inner.iss()
    }
    /// The `sub` claim, if present.
    fn sub(&self) -> Option<&str> {
        self.inner.sub()
    }
    /// The `jwks` carried in the statement (the subject's federation keys)
    /// as a `{"keys": [...]}` dict. Raises `BadRequestError` if absent.
    fn jwks<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let jwks = self.inner.jwks().map_err(err)?;
        to_py(py, &drop_federation_oct_keys(py, jwks))
    }
    /// A metadata sub-document, e.g. `metadata("openid_provider")`, or `None`.
    fn metadata<'py>(&self, py: Python<'py>, kind: &str) -> PyResult<Option<Bound<'py, PyAny>>> {
        match self.inner.metadata(kind) {
            Some(v) => to_py(py, &v).map(Some),
            None => Ok(None),
        }
    }
    /// The `authority_hints` list (empty if absent).
    fn authority_hints(&self) -> Vec<String> {
        self.inner.authority_hints()
    }
    fn __repr__(&self) -> String {
        format!(
            "EntityStatement(iss={:?}, sub={:?})",
            self.inner.iss(),
            self.inner.sub()
        )
    }
}

// ---------------------------------------------------------------------------
// ResolvedEntity
// ---------------------------------------------------------------------------

/// A successful resolve response, bound to a configured trust anchor.
#[pyclass(
    module = "pygrindvakt.federation",
    name = "ResolvedEntity",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct ResolvedEntity {
    pub inner: gf::ResolvedEntity,
}

impl ResolvedEntity {
    pub fn wrap(inner: gf::ResolvedEntity) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl ResolvedEntity {
    /// The trust anchor that issued the resolve response.
    #[getter]
    fn issuer(&self) -> &str {
        &self.inner.issuer
    }
    /// The resolved entity id.
    #[getter]
    fn subject(&self) -> &str {
        &self.inner.subject
    }
    /// The resolved (policy-applied) `metadata` object as a dict.
    #[getter]
    fn metadata<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner.metadata)
    }
    /// The subject's federation signing keys from the entity configuration at
    /// the start of the returned trust chain, as a `{"keys": [...]}` dict.
    #[getter]
    fn subject_jwks<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(
            py,
            &drop_federation_oct_keys(py, self.inner.subject_jwks.clone()),
        )
    }
    /// Raw `trust_marks` entries from the trust anchor's signed resolve
    /// response (empty if absent). NOT verified: check the type, subject,
    /// issuer signature and lifetime before trusting any entry.
    #[getter]
    fn trust_marks<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_py(py, &self.inner.trust_marks)
    }
    /// Expiry (seconds since epoch) of the resolved result: the earlier of
    /// the resolve response's `exp` and the earliest expiry in its validated
    /// trust chain. Use it to bound caching.
    #[getter]
    fn exp(&self) -> Option<u64> {
        self.inner.exp
    }
    fn __repr__(&self) -> String {
        format!(
            "ResolvedEntity(issuer={:?}, subject={:?}, exp={:?})",
            self.inner.issuer, self.inner.subject, self.inner.exp
        )
    }
}

// ---------------------------------------------------------------------------
// CollectionEntity
// ---------------------------------------------------------------------------

/// One entity returned by a trust anchor's collection (listing) endpoint,
/// with its UI presentation flattened for a discovery page.
#[pyclass(
    module = "pygrindvakt.federation",
    name = "CollectionEntity",
    frozen,
    from_py_object,
    eq
)]
#[derive(Clone, PartialEq)]
pub struct CollectionEntity {
    pub inner: gf::CollectionEntity,
}

impl CollectionEntity {
    pub fn wrap(inner: gf::CollectionEntity) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl CollectionEntity {
    #[new]
    #[pyo3(signature = (*, entity_id, display_name, logo_uri = None))]
    fn new(entity_id: String, display_name: String, logo_uri: Option<String>) -> Self {
        Self {
            inner: gf::CollectionEntity {
                entity_id,
                display_name,
                logo_uri,
            },
        }
    }
    /// The entity identifier (the OP / IdP to authenticate against).
    #[getter]
    fn entity_id(&self) -> &str {
        &self.inner.entity_id
    }
    /// A human-friendly name: the entity-type display name, else the
    /// `federation_entity` display name, else the entity id.
    #[getter]
    fn display_name(&self) -> &str {
        &self.inner.display_name
    }
    /// An optional logo URL for the discovery page.
    #[getter]
    fn logo_uri(&self) -> Option<&str> {
        self.inner.logo_uri.as_deref()
    }
    fn __repr__(&self) -> String {
        format!(
            "CollectionEntity(entity_id={:?}, display_name={:?}, logo_uri={:?})",
            self.inner.entity_id, self.inner.display_name, self.inner.logo_uri
        )
    }
}

// ---------------------------------------------------------------------------
// Entity statements: build / decode / verify
// ---------------------------------------------------------------------------

/// Build and sign a self-issued Entity Configuration JWT
/// (`iss == sub == entity_id`, `typ = entity-statement+jwt`).
///
/// `public_jwks` is the `{"keys": [...]}` dict to publish (normally
/// `key.to_public_jwks()`), `metadata` the per-entity-type metadata object,
/// `trust_marks` an optional list of trust mark objects, and `lifetime` the
/// validity in seconds.
#[pyfunction]
#[pyo3(signature = (key, entity_id, public_jwks, authority_hints, metadata, trust_marks = None, lifetime = 3600))]
#[allow(clippy::too_many_arguments)]
fn build_entity_configuration(
    py: Python<'_>,
    key: &SigningKey,
    entity_id: &str,
    public_jwks: &Bound<'_, PyAny>,
    authority_hints: Vec<String>,
    metadata: &Bound<'_, PyAny>,
    trust_marks: Option<&Bound<'_, PyAny>>,
    lifetime: u64,
) -> PyResult<String> {
    let public_jwks = jwks_from_py(public_jwks)?;
    warn_if_publishing_oct(
        py,
        &public_jwks,
        "federation.build_entity_configuration()",
        "federation entities sign with asymmetric keys; trust chain validators will ignore it",
    );
    let metadata: Value = from_py(metadata)?;
    let trust_marks: Vec<Value> = match trust_marks {
        Some(t) if !t.is_none() => from_py(t)?,
        _ => Vec::new(),
    };
    gf::build_entity_configuration(
        &key.inner,
        entity_id,
        &public_jwks,
        &authority_hints,
        metadata,
        &trust_marks,
        lifetime,
    )
    .map_err(err)
}

/// Decode an entity statement WITHOUT verifying its signature.
///
/// SECURITY: inspection only (e.g. reading `authority_hints`). Never trust
/// these claims.
#[pyfunction]
fn decode_unverified(token: &str) -> PyResult<EntityStatement> {
    gf::decode_unverified(token)
        .map(EntityStatement::wrap)
        .map_err(err)
}

/// Verify an entity statement's signature against a JWKS dict and require
/// `typ = entity-statement+jwt` and a present `exp`.
#[pyfunction]
fn verify(py: Python<'_>, token: &str, jwks: &Bound<'_, PyAny>) -> PyResult<EntityStatement> {
    refuse_mac_or_none(py, token)?;
    let jwks = verifier_jwks(py, jwks)?;
    gf::verify(token, &jwks)
        .map(EntityStatement::wrap)
        .map_err(err)
}

/// Verify a trust-anchor-signed JWT against a JWKS dict, requiring the given
/// `typ` header (e.g. `RESOLVE_RESPONSE_TYP`) and a present `exp`.
#[pyfunction]
fn verify_typed(
    py: Python<'_>,
    token: &str,
    jwks: &Bound<'_, PyAny>,
    typ: &str,
) -> PyResult<EntityStatement> {
    refuse_mac_or_none(py, token)?;
    let jwks = verifier_jwks(py, jwks)?;
    gf::verify_typed(token, &jwks, typ)
        .map(EntityStatement::wrap)
        .map_err(err)
}

/// Verify a self-issued Entity Configuration using the keys it carries
/// (`iss == sub`, signature validates against the embedded `jwks`).
#[pyfunction]
fn verify_self_signed(py: Python<'_>, token: &str) -> PyResult<EntityStatement> {
    refuse_mac_or_none(py, token)?;
    gf::verify_self_signed(token)
        .map(EntityStatement::wrap)
        .map_err(err)
}

// ---------------------------------------------------------------------------
// Trust marks
// ---------------------------------------------------------------------------

/// `typ` header of a trust mark JWT (OpenID Federation 1.0 section 7.1).
const TRUST_MARK_TYP: &str = "trust-mark+jwt";

/// Verify one trust mark JWT; returns the validated claims or a reason.
fn verify_one_trust_mark(
    token: &str,
    jwks: &JwkSet,
    required_type: &str,
    subject: &str,
    issuer: &str,
    require_exp: bool,
) -> Result<EntityStatement, String> {
    // `iat` is REQUIRED in a trust mark (OpenID Federation 1.0 section 7.1).
    let mut validation = Validation::new()
        .with_typ(TRUST_MARK_TYP)
        .with_subject(subject)
        .with_issuer(issuer)
        .require_iat()
        // Without `kid` the try-every-key fallback would verify the mark under
        // any key in a mixed-trust set.
        .require_kid();
    if require_exp {
        validation = validation.require_exp();
    }
    let claims = match grindvakt::jwt::verify_with_jwks(jwks, token, &validation) {
        Ok(c) => c,
        Err(e) => return Err(e.to_string()),
    };
    let value = match serde_json::to_value(&claims) {
        Ok(v) => v,
        Err(e) => return Err(e.to_string()),
    };
    if value.get("trust_mark_type").and_then(Value::as_str) != Some(required_type) {
        return Err("inner trust_mark_type does not match the entry".into());
    }
    if value.get("iss").and_then(Value::as_str).is_none() {
        return Err("trust mark has no iss".into());
    }
    if value.get("delegation").is_some() {
        return Err("delegated trust marks are not supported (no delegation owner keys)".into());
    }
    Ok(EntityStatement::wrap(gf::EntityStatement { claims: value }))
}

/// Verify the trust marks of a resolved entity (OpenID Federation 1.0
/// section 7). Core stores them raw; this verifies the ones of
/// `required_type` against the trust mark ISSUER's keys.
#[pyfunction]
#[pyo3(signature = (marks, issuer_jwks, required_type, *, subject, issuer, require_exp=true))]
fn verify_trust_marks(
    py: Python<'_>,
    marks: &Bound<'_, PyAny>,
    issuer_jwks: &Bound<'_, PyAny>,
    required_type: &str,
    subject: &str,
    issuer: &str,
    require_exp: bool,
) -> PyResult<Vec<EntityStatement>> {
    let marks: Vec<Value> = from_py(marks)?;
    let jwks = verifier_jwks(py, issuer_jwks)?;
    let mut verified = Vec::new();
    let mut seen = false;
    let mut last_reason = String::new();
    let mut refused: Option<PyErr> = None;
    for entry in &marks {
        let Some(obj) = entry.as_object() else {
            continue;
        };
        if obj.get("trust_mark_type").and_then(Value::as_str) != Some(required_type) {
            continue;
        }
        seen = true;
        let Some(token) = obj.get("trust_mark").and_then(Value::as_str) else {
            last_reason = "entry has no string trust_mark".into();
            continue;
        };
        // A MAC/none entry is a per-entry failure; it must not hide a valid mark.
        if let Err(e) = refuse_mac_or_none(py, token) {
            refused.get_or_insert(e);
            continue;
        }
        match verify_one_trust_mark(token, &jwks, required_type, subject, issuer, require_exp) {
            Ok(stmt) => verified.push(stmt),
            Err(reason) => last_reason = reason,
        }
    }
    if !verified.is_empty() {
        return Ok(verified);
    }
    if let Some(e) = refused {
        return Err(e);
    }
    if !seen {
        return Err(with_code(
            py,
            AuthnError::new_err(format!("no trust mark of type {required_type:?} present")),
            "trust_mark_missing",
        ));
    }
    Err(with_code(
        py,
        AuthnError::new_err(format!(
            "no trust mark of type {required_type:?} verified: {last_reason}"
        )),
        "trust_mark_invalid",
    ))
}

// ---------------------------------------------------------------------------
// Networked: fetch / resolve / keys / collection
// ---------------------------------------------------------------------------

/// Fetch an entity's configuration JWT from
/// `<entity_id>/.well-known/openid-federation`. Returns the raw compact JWS.
#[pyfunction]
#[pyo3(signature = (http, entity_id))]
fn fetch_entity_configuration(
    py: Python<'_>,
    http: Option<&Bound<'_, PyAny>>,
    entity_id: String,
) -> PyResult<String> {
    let (http, failures) = extract_http_client(http)?;
    crate::runtime::block_on(py, async move {
        gf::fetch_entity_configuration(&http, &entity_id).await
    })?
    .map_err(|e| failures.err(py, e))
}

/// Resolve `sub`'s metadata by delegating to each configured trust anchor's
/// `federation_resolve_endpoint` (OpenID Federation 1.0 section 10).
///
/// `trust_anchors` maps trust anchor entity id -> its trusted JWKS dict. For
/// each anchor the trust anchor's own entity configuration is fetched and
/// verified, then `<federation_resolve_endpoint>?sub=...&trust_anchor=...`
/// is called; the resolve response (`typ = resolve-response+jwt`) and the
/// `trust_chain` it carries are fully validated. The first anchor that
/// succeeds wins; otherwise the last error is raised.
#[pyfunction]
#[pyo3(signature = (http, sub, trust_anchors))]
fn resolve_via_trust_anchors(
    py: Python<'_>,
    http: Option<&Bound<'_, PyAny>>,
    sub: String,
    trust_anchors: &Bound<'_, PyAny>,
) -> PyResult<ResolvedEntity> {
    let (http, failures) = extract_http_client(http)?;
    let trust_anchors: HashMap<String, JwkSet> = from_py::<HashMap<String, JwkSet>>(trust_anchors)?
        .into_iter()
        .map(|(id, jwks)| (id, drop_federation_oct_keys(py, jwks)))
        .collect();
    crate::runtime::block_on(py, async move {
        gf::resolve_via_trust_anchors(&http, &sub, &trust_anchors).await
    })?
    .map(ResolvedEntity::wrap)
    .map_err(|e| failures.err(py, e))
}

/// Resolve an entity type's key set from its metadata (OpenID Federation 1.1
/// section 5.2.1): inline `jwks`, else `signed_jwks_uri` (verified against
/// `subject_fed_jwks`), else `jwks_uri`. Returns a `{"keys": [...]}` dict.
///
/// Symmetric (`oct`) keys are dropped from the result with a `UserWarning`
/// (OIDC Core section 10.1: published key sets must not carry them). This also
/// filters inline `jwks` metadata. The drop is unconditional.
#[pyfunction]
#[pyo3(signature = (http, metadata, subject_entity_id, subject_fed_jwks))]
fn entity_metadata_jwks<'py>(
    py: Python<'py>,
    http: Option<&Bound<'py, PyAny>>,
    metadata: &Bound<'py, PyAny>,
    subject_entity_id: String,
    subject_fed_jwks: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let (http, failures) = extract_http_client(http)?;
    let metadata: Value = from_py(metadata)?;
    let subject_fed_jwks = verifier_jwks(py, subject_fed_jwks)?;
    let jwks = crate::runtime::block_on(py, async move {
        gf::entity_metadata_jwks(&http, &metadata, &subject_entity_id, &subject_fed_jwks).await
    })?
    .map_err(|e| failures.err(py, e))?;
    let jwks = drop_oct_keys(
        py,
        jwks,
        "published JWKS",
        "OPs must not publish symmetric keys (OIDC Core section 10.1)",
    );
    to_py(py, &jwks)
}

/// Fetch and verify a signed JWK Set document (`typ = jwk-set+jwt`) from
/// `signed_jwks_uri`. The signature must validate against
/// `subject_fed_jwks` and the `sub` must equal `subject_entity_id`. Returns a
/// `{"keys": [...]}` dict. Symmetric (`oct`) keys are dropped from the result
/// with a `UserWarning` (OIDC Core section 10.1).
#[pyfunction]
#[pyo3(signature = (http, signed_jwks_uri, subject_entity_id, subject_fed_jwks))]
fn fetch_signed_jwks<'py>(
    py: Python<'py>,
    http: Option<&Bound<'py, PyAny>>,
    signed_jwks_uri: String,
    subject_entity_id: String,
    subject_fed_jwks: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let (http, failures) = extract_http_client(http)?;
    let subject_fed_jwks = verifier_jwks(py, subject_fed_jwks)?;
    let jwks = crate::runtime::block_on(py, async move {
        gf::fetch_signed_jwks(
            &http,
            &signed_jwks_uri,
            &subject_entity_id,
            &subject_fed_jwks,
        )
        .await
    })?
    .map_err(|e| failures.err(py, e))?;
    let jwks = drop_oct_keys(
        py,
        jwks,
        "published JWKS",
        "OPs must not publish symmetric keys (OIDC Core section 10.1)",
    );
    to_py(py, &jwks)
}

/// Fetch the entities of `entity_type` (e.g. `"openid_provider"`) from a
/// trust anchor's collection endpoint (`<endpoint>?entity_type=...`) and
/// flatten their UI info for a discovery page.
#[pyfunction]
#[pyo3(signature = (http, collection_endpoint, entity_type))]
fn fetch_collection(
    py: Python<'_>,
    http: Option<&Bound<'_, PyAny>>,
    collection_endpoint: String,
    entity_type: String,
) -> PyResult<Vec<CollectionEntity>> {
    let (http, failures) = extract_http_client(http)?;
    let entities = crate::runtime::block_on(py, async move {
        gf::fetch_collection(&http, &collection_endpoint, &entity_type).await
    })?
    .map_err(|e| failures.err(py, e))?;
    Ok(entities.into_iter().map(CollectionEntity::wrap).collect())
}

/// Parse a collection-endpoint response body
/// (`{"entities": [{"entity_id": ..., "entity_types": [...], "ui_infos": {...}}]}`)
/// into `CollectionEntity` objects. Entries without an `entity_id`, or that do
/// not advertise `entity_type` in `entity_types`, are skipped.
#[pyfunction]
fn parse_collection(body: &Bound<'_, PyAny>, entity_type: &str) -> PyResult<Vec<CollectionEntity>> {
    let body: Value = from_py(body)?;
    Ok(gf::parse_collection(&body, entity_type)
        .into_iter()
        .map(CollectionEntity::wrap)
        .collect())
}

// ---------------------------------------------------------------------------
// Metadata policy
// ---------------------------------------------------------------------------

/// Apply a metadata policy (OpenID Federation 1.0 section 6) to a metadata
/// object and return the resulting dict; the input is not modified.
///
/// Supports the `value`, `default`, `add`, `one_of`, `subset_of`,
/// `superset_of` and `essential` operators. Raises `AuthnError` when the
/// metadata violates a constraint and `BadRequestError` for a malformed
/// policy.
#[pyfunction]
fn apply_policy<'py>(
    py: Python<'py>,
    metadata: &Bound<'py, PyAny>,
    policy: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let mut metadata: Map<String, Value> = from_py(metadata)?;
    let policy: Map<String, Value> = from_py(policy)?;
    gf::apply_policy(&mut metadata, &policy).map_err(err)?;
    to_py(py, &metadata)
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "federation")?;
    m.add_class::<EntityStatement>()?;
    m.add_class::<ResolvedEntity>()?;
    m.add_class::<CollectionEntity>()?;
    m.add_function(wrap_pyfunction!(build_entity_configuration, &m)?)?;
    m.add_function(wrap_pyfunction!(decode_unverified, &m)?)?;
    m.add_function(wrap_pyfunction!(verify, &m)?)?;
    m.add_function(wrap_pyfunction!(verify_typed, &m)?)?;
    m.add_function(wrap_pyfunction!(verify_self_signed, &m)?)?;
    m.add_function(wrap_pyfunction!(verify_trust_marks, &m)?)?;
    m.add_function(wrap_pyfunction!(fetch_entity_configuration, &m)?)?;
    m.add_function(wrap_pyfunction!(resolve_via_trust_anchors, &m)?)?;
    m.add_function(wrap_pyfunction!(entity_metadata_jwks, &m)?)?;
    m.add_function(wrap_pyfunction!(fetch_signed_jwks, &m)?)?;
    m.add_function(wrap_pyfunction!(fetch_collection, &m)?)?;
    m.add_function(wrap_pyfunction!(parse_collection, &m)?)?;
    m.add_function(wrap_pyfunction!(apply_policy, &m)?)?;
    m.add("ENTITY_STATEMENT_TYP", gf::ENTITY_STATEMENT_TYP)?;
    m.add("RESOLVE_RESPONSE_TYP", gf::RESOLVE_RESPONSE_TYP)?;
    m.add("JWK_SET_TYP", gf::JWK_SET_TYP)?;
    m.add("TRUST_MARK_TYP", TRUST_MARK_TYP)?;
    Ok(())
}
