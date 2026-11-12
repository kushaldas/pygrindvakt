# pygrindvakt

Python bindings for [grindvakt](https://github.com/kushaldas/grindvakt) **0.12.0**, a
runtime-agnostic Rust library for **OAuth 2.0**, **OpenID Connect** and
**OpenID Federation 1.1**: an OpenID Provider engine, a Relying Party toolkit,
federation trust-chain resolution, DPoP (RFC 9449), and the JOSE/key primitives
underneath. Built with [PyO3](https://pyo3.rs) 0.29 + [maturin](https://www.maturin.rs)
(abi3, Python ≥ 3.10).

The binding mirrors grindvakt's modules as Python submodules:
`pygrindvakt.{http, keys, client, metadata, request, tokens, provider, dpop, rp,
federation, discovery, jwt, pkce, mac, util}`. It is **web-framework agnostic**:
requests come in as plain dicts/strings, responses go out as a `Response`
(`status`, `headers`, `body`), and the same `Provider` object works under Flask,
Django, FastAPI, or anything else. See `examples/` for complete adapters.

## Example - an OpenID Provider token endpoint (Flask)

```python
from flask import Flask, request, Response as FlaskResponse
from pygrindvakt import OAuthError, client, keys, metadata, provider, tokens

ISSUER = "https://op.example.com"
op = provider.Provider(
    metadata.ProviderMetadata(ISSUER),
    keys.signing_key_from_pem(open("op-key.pem", "rb").read(), kid="op-1"),
    client.InMemoryClientStore(
        [
            client.Client(
                "demo",
                client_secret="s3cret",
                redirect_uris=["https://rp.example.com/cb"],
            ),
        ]
    ),
    tokens.TokenCodec("a-long-random-secret"),
    token_use_store=provider.InMemoryTokenUseStore(),  # or RedisStore(...) across workers
)

app = Flask(__name__)


def to_flask(r):
    return FlaskResponse(r.body, status=r.status, headers=r.headers)


@app.post("/token")
def token():
    try:
        tr = op.handle_token_request(
            list(request.form.items(multi=True)),
            f"{ISSUER}/token",  # from config, never from Host
            auth_header=request.headers.get("Authorization"),
        )
        return to_flask(tr.to_response())
    except OAuthError as e:
        return to_flask(e.to_response())  # correct status, JSON body, no-store
```

Discovery, JWKS, authorization and userinfo follow the same shape:
`op.discovery_document()`, `op.jwks_document()`,
`op.validate_authorization_request(req)` / `op.authorization_redirect(req, sub, claims)`,
`op.userinfo(access_token)`.

## Example - a Relying Party

```python
from pygrindvakt import http, rp, pkce, util

http_client = http.ReqwestClient()  # never follows redirects, bounded body
md = rp.discover(http_client, "https://op.example.com")
info = rp.ProviderInfo.from_metadata(md)
me = rp.RpClient("demo", "https://rp.example.com/cb", client_secret="s3cret")

state, nonce, verifier = (
    util.random_token(24),
    util.random_token(24),
    util.random_token(32),
)
url = rp.authorization_url(
    info, me, state, nonce, code_challenge=pkce.s256_challenge(verifier)
)
# ... redirect the browser to `url`; on the callback:
tokens_ = rp.exchange_code(http_client, info, me, code, code_verifier=verifier)
jwks = rp.fetch_jwks(http_client, info.jwks_uri, info.issuer)
claims = rp.verify_id_token(
    jwks, tokens_.id_token, info.issuer, "demo", nonce, ["ES256"]
)
if info.userinfo_endpoint is not None:  # OPs may omit UserInfo
    userinfo = rp.fetch_userinfo(
        http_client,
        info.userinfo_endpoint,
        tokens_.access_token,
        claims["sub"],
        info.issuer,
    )
```

On the callback, parse the query with `rp.parse_authorization_response(params)`
(fail-closed; it never exposes the raw `error_description`) before reading
`code`. Check `state` and compare `iss` yourself. See the
[RP guide](https://pygrindvakt.readthedocs.io/en/latest/guides/rp.html).

> **Note:** `from pygrindvakt import http` shadows the standard-library `http`
> package in that module. If you also need `http.HTTPStatus` and friends, use
> `from pygrindvakt import http as gv_http` or `import pygrindvakt.http`.

> **Security:** `verify_id_token` requires the expected nonce and an explicit
> signing-algorithm allowlist. Passing `None`
> raises unless you also pass `unsafe_skip_nonce_check=True`, which emits a
> `UserWarning`. Other guards the binding adds on top of grindvakt: duplicate
> `client_id`s and unknown `Client` fields are rejected, reserved id_token claim
> names in `extra_claims` raise, and the built-in HTTP client refuses to follow
> redirects. Never send `str(exc)` of a `GrindvaktError` to a client; only
> `OAuthError.to_response()` / `.to_redirect()` output is client-safe. See the
> [security guide](https://pygrindvakt.readthedocs.io/en/latest/guides/security.html).

## Concurrency, workers and stores

grindvakt is `async` Rust; the Python API is synchronous. Each call runs on a
process-wide tokio runtime with the GIL released, so threads (gunicorn `gthread`,
FastAPI's threadpool) run in parallel. The runtime is rebuilt lazily after
`fork`, so a `Provider` built in a gunicorn master keeps working in workers,
unless it uses a `RedisStore`, which is process-bound and fails closed in a
forked child (build it and its `Provider` in each worker).

`http.ReqwestClient` is frozen and safe to share across threads (the GIL is
released during I/O, so calls run in parallel); `http=None` uses a process-wide
default instance with the same properties. Its connection pool is keyed by PID
and rebuilt lazily in a forked child, inherited connections are never reused,
and a fork while another thread has a request in flight is not supported. Fork only while no other thread is inside a pygrindvakt call: an
internal lock held by another thread at fork time stays locked in the child
and can deadlock it. Create the `ReqwestClient` before or after fork, but a `RedisStore`
*after*. A Python HTTP client runs on the calling thread holding the GIL, so if
you share one across threads it must be thread-safe itself; re-entrant calls
into pygrindvakt from it cost a helper thread. See
[ADR 0001](docs/adr/0001-sync-api-over-embedded-tokio-runtime.md).

State that must be shared across processes:

- **Token-use store** (one-time codes / refresh tokens / assertion `jti`s):
  `provider.RedisStore(url)` (construct it *after* fork) or any object with
  `consume(token_hash, ttl_secs) -> bool`.
- **Client store**: `client.InMemoryClientStore` or any object with
  `get(client_id)` / `put(client)` (Django ORM, a cache, ...).
- **DPoP replay store**: `dpop.InMemoryReplayStore` or any object with
  `record(jti, ttl_secs) -> bool`.
- **Outbound HTTP**: `http.ReqwestClient` or any object with `get(url)` /
  `post_form(url, form, headers)` returning `(status, body, content_type)`;
  an optional `post_json(url, body, headers)` is used for JSON POSTs.

Python-implemented stores **fail closed**: an exception is logged through
`sys.unraisablehook` and surfaces to the client as `server_error`.

## HSM / PKCS#11 signing

```python
from pygrindvakt import keys

key = keys.signing_key_from_pkcs11(
    "/usr/lib/softhsm/libsofthsm2.so", "1234", "op-signing-key", "ES256", kid="hsm-1"
)
```

> Prefer building the wheel on (or against) the target host when deploying with
> an HSM: the PKCS#11 module is `dlopen`-ed at runtime from that host.

## Development

Installs must go through `sfw` (Socket Firewall).

A Rust toolchain matching `Cargo.toml`'s `rust-version` (1.89 or newer) is required.

```bash
sfw uv sync --frozen --only-group dev   # the locked test / lint / typecheck tools, as in CI
sfw uv pip install --python .venv/bin/python "maturin==1.14.1"
VIRTUAL_ENV=$PWD/.venv .venv/bin/maturin develop --release --uv
.venv/bin/python -m pytest tests/            # PKCS#11 / Redis tests auto-skip
cargo clippy --release -- -D warnings && cargo fmt --check
REDIS_URL=redis://127.0.0.1/ .venv/bin/python -m pytest tests/ -m redis
```

`just` wraps the same gates: `just check` runs ruff lint, ruff format check,
`mypy --strict` over `tests/typecheck_usage.py`, pytest and `just docs-version`
(which fails if the grindvakt version documented here and in `docs/index.rst`
has drifted from `Cargo.lock`, or the `docs/conf.py` fallback `release` from
`Cargo.toml`; it does not read `CHANGELOG.md`); `just --list` shows the rest. `just release
<version>` creates and pushes the signed tag that triggers the release workflow
(it refuses a tag that disagrees with `Cargo.toml` / `pyproject.toml`).

When the `grindvakt` dependency is bumped, update the version in this README, in
`docs/index.rst` (prose and the compatibility table) and in `CHANGELOG.md` in
the same commit; `just docs-version` checks the README and `docs/index.rst`, not
the changelog.

## Documentation

Guides and the full API reference: <https://pygrindvakt.readthedocs.io/en/latest/>.
Design decisions live in `docs/adr/`; release-by-release changes, including
every breaking change, in [`CHANGELOG.md`](CHANGELOG.md).

## Type stubs

The package ships `.pyi` stubs for every submodule (`py.typed` marks the package as fully typed).

## License

BSD-2-Clause.
