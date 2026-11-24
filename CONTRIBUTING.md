# Contributing to pygrindvakt

Read src/http.rs, src/client.rs, src/provider.rs, src/dpop.rs, src/jwt.rs first: they are the reference implementations.

- One `src/<mod>.rs` per grindvakt module, exposing `pub fn register(py, parent)` that calls
  `crate::convert::new_submodule(py, parent, "<mod>")` and adds classes/functions. `lib.rs` already
  declares the module and calls register; do NOT edit lib.rs.
- Wrap upstream types as `#[pyclass(module = "pygrindvakt.<mod>", name = "X", frozen, from_py_object)] #[derive(Clone)] pub struct X { pub inner: grindvakt::<mod>::X }`
  with `pub fn wrap(inner) -> Self`. Handles holding Arc use `frozen` + `skip_from_py_object`.
- Getters via `#[getter]`; `&str`/`Option<&str>` returned by borrow from &self; Vec/BTreeMap cloned.
- JSON-shaped values (serde_json::Value, Jwk, JwkSet, Claims, Map) cross as native Python objects via
  `crate::convert::{to_py, from_py}` (pythonize). JwkSet in = dict `{"keys": [...]}`; use `crate::jwt::jwks_from_py`.
- Errors: `grindvakt::Error` -> `crate::errors::err`; `OAuthError` -> `crate::errors::oauth_err(py, &e)`;
  Display-only -> `crate::errors::{config_err, crypto_err, internal_err, jose_err}`.
- Async upstream functions: clone/own all inputs, then
  `let r = crate::runtime::block_on(py, async move { ... })?;` (returns PyResult<Output>), then map errors.
  Functions taking `http: &Arc<dyn HttpClient>` accept a Python arg `http: Option<&Bound<PyAny>>` and call
  `crate::http::extract_http_client(http)?` (None -> built-in default client). Put `http` as the FIRST
  positional parameter with default None (`#[pyo3(signature = (http = None, ...))]` is NOT allowed since
  later params are required — so instead make `http` a required positional that accepts None:
  `#[pyo3(signature = (http, issuer))]` with `http: Option<&Bound<'_, PyAny>>`).
- Optional parameters: always explicit `#[pyo3(signature = (...))]`. Keyword-only struct constructors use `*`.
- Enums become lowercase strings; enum-like Rust values built via static constructors.
- `__repr__` on every class: `Name(field=..., field=...)` with identifying fields only.
- Security downgrades need an explicit `unsafe_*=False` kwarg and, when enabled, `crate::convert::warn(py, "...")`.
- Secrets passed as `str` get a `/// SECURITY:` doc note. Bytes in as `&[u8]`, out as `PyBytes`.
- No `py.detach` for CPU work; only runtime::block_on detaches.
- Doc comments on every pyclass/pyfunction (they become `__doc__`).
- Build: `cargo build --release`. Install + test: `VIRTUAL_ENV=$PWD/.venv .venv/bin/maturin develop --release --uv && .venv/bin/python -m pytest tests/<your file> -q`.
- Re-entrant calls (an adapter calling back into pygrindvakt) are handled by runtime::block_on on a helper thread.
- If a build error is in a file you do not own, another contributor is mid-edit: wait ~60s and retry.

## Docs, changelog and releases

- `docs/api/<mod>.rst` is hand-written from the stubs and the Rust doc comments. If you change a
  `#[pyo3(signature = ...)]`, a doc comment or a guard, edit the matching `.. py:` block in the same
  PR: `tests/test_stubs.py` keeps the stubs honest with the runtime, and nothing else keeps the docs honest.
- Mark behaviour that differs from the previous release with `.. versionadded:: <v>` /
  `.. versionchanged:: <v>` on the affected directive; `/en/latest` is the only Read the Docs build, so
  that is how a reader tells what is new.
- User-visible changes get a bullet under `## Unreleased` in `CHANGELOG.md` (add the heading above the
  latest release if it is missing; the release commit renames it to `## [<v>] - <date>`); keep one section of each type per release — entries from merged
  branches were concatenated once already.
  The release workflow publishes that `## [<v>] - <date>` section as the body of the GitHub release for
  tag `v<v>` (and fails if the section is missing), so keep the heading in exactly that form.
- Docs build with `-W` on Read the Docs and have no CI job: run
  `.venv/bin/python -m sphinx -b html -W docs docs/_build/html` (needs `--group docs`) before pushing
  docs changes, and `just docs-version` when you touch the grindvakt version named in `README.md` /
  `docs/index.rst`. At release time also bump the fallback `release` in `docs/conf.py`
  (Read the Docs does not install the package); `just docs-version` checks it.
- New fail-closed guards and their escape hatches are recorded as ADRs (`docs/adr/`): a new record that
  extends the list in ADR 0003/0004, plus a row in the `docs/guides/security.rst` guard table and, if it
  weakens something, an entry in its "Footguns" section.
