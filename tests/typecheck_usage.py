"""Static typing smoke test, checked in CI with ``mypy --strict`` (not run by pytest).

Exercises the ``http`` argument of ``rp`` / ``federation`` / ``discovery`` with
the built-in ``ReqwestClient``, ``None`` and a custom protocol client.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pygrindvakt.http
from pygrindvakt import (
    AuthnError,
    GrindvaktError,
    InternalError,
    OAuthError,
    client,
    discovery,
    federation,
    jwt,
    keys,
    metadata,
    provider,
    request,
    rp,
    testing,
    tokens,
)

if TYPE_CHECKING:
    from collections.abc import Callable


class TupleClient:
    """Custom client returning the plain tuple form."""

    def get(self, url: str) -> tuple[int, bytes, str | None]:
        return 200, b"{}", "application/json"

    def post_form(
        self,
        url: str,
        form: list[tuple[str, str]],
        headers: list[tuple[str, str]],
    ) -> tuple[int, bytes, str | None]:
        return 200, b"{}", None


class FetchResponseClient:
    """Custom client returning ``HttpFetchResponse``."""

    def get(self, url: str) -> pygrindvakt.http.HttpFetchResponse:
        return pygrindvakt.http.HttpFetchResponse(200, b"{}", "application/json")

    def post_form(
        self,
        url: str,
        form: list[tuple[str, str]],
        headers: list[tuple[str, str]],
    ) -> pygrindvakt.http.HttpFetchResponse:
        return pygrindvakt.http.HttpFetchResponse(200, b"{}")


class HeadersClient(TupleClient):
    """``get`` accepts request headers (``HttpClientWithHeadersProtocol``)."""

    def get(self, url: str, headers: list[tuple[str, str]] | None = None) -> tuple[int, bytes, str | None]:
        return 200, b"{}", "application/json"


class GetWithHeadersClient(TupleClient):
    """Provides ``get_with_headers`` (``HttpClientGetWithHeadersProtocol``)."""

    def get_with_headers(self, url: str, headers: list[tuple[str, str]]) -> tuple[int, bytes, str | None]:
        return 200, b"{}", "application/json"


def use_all() -> None:
    reqwest = pygrindvakt.http.ReqwestClient(request_timeout=5)
    custom = TupleClient()
    fetch = FetchResponseClient()

    status, body, content_type = reqwest.post_json("https://op.example.com/x", {"a": [1, None]}, [("X-A", "b")])
    reqwest.post_json("https://op.example.com/x", "scalar")
    _ = (status, body, content_type)

    md = rp.discover(reqwest, "https://op.example.com")
    rp.discover(None, "https://op.example.com")
    rp.discover(custom, "https://op.example.com")
    rp.discover(fetch, "https://op.example.com")
    info = rp.ProviderInfo.from_metadata(md)
    me = rp.RpClient("demo", "https://rp.example.com/cb", client_secret="s")
    rp.exchange_code(reqwest, info, me, "code")
    rp.exchange_code(custom, info, me, "code", code_verifier="v")
    rp.exchange_code(reqwest, info, me, "code", "v", redirect_uri="https://rp.example.com/alt")
    url, state, nonce, verifier = rp.begin(info, me)
    check: tuple[str, str, str, str | None] = (url, state, nonce, verifier)
    del check
    rp.begin(
        info,
        me,
        extra={"prompt": "login"},
        redirect_uri="https://rp.example.com/alt",
        pkce=False,
    )
    rp.authorization_url(info, me, state, nonce, redirect_uri=None)
    logout: str = rp.end_session_url(info, id_token_hint="t", client=me, state="s", extra={"k": "v"})
    rpc_logout = rp.RpClient(
        "demo",
        "https://rp.example.com/cb",
        post_logout_redirect_uris=["https://rp.example.com/bye"],
    )
    registered: tuple[str, ...] = rpc_logout.post_logout_redirect_uris
    rp.end_session_url(info, client=rpc_logout, post_logout_redirect_uri="https://rp.example.com/bye")
    del registered
    rpc_login = rp.RpClient(
        "demo",
        "https://rp.example.com/cb",
        redirect_uris=["https://rp.example.com/alt"],
        allow_unregistered_redirect_uri=False,
    )
    login_uris: tuple[str, ...] = rpc_login.redirect_uris
    allow_any: bool = rpc_login.allow_unregistered_redirect_uri
    del login_uris, allow_any
    es: str | None = info.end_session_endpoint
    rp.ProviderInfo(
        "https://op.example.com",
        "https://op.example.com/a",
        "https://op.example.com/t",
        end_session_endpoint="https://op.example.com/logout",
    )
    rp.ProviderInfo(
        "https://op.example.com",
        "https://op.example.com/a",
        "https://op.example.com/t",
        end_session_endpoint="https://logout.other.example/logout",
        allow_cross_origin_end_session=True,
    )
    xo: rp.ProviderInfo = rp.ProviderInfo.from_metadata(md, allow_cross_origin_end_session=True)
    del xo
    acr: list[str] | None = md.acr_values_supported
    flag: bool | None = md.backchannel_logout_supported
    rev: str | None = md.revocation_endpoint
    md.acr_values_supported = None
    md.end_session_endpoint = "https://op.example.com/logout"
    raw: dict[str, object] | None = md.raw
    dumped: dict[str, object] = md.to_dict(exclude_defaults=True)
    del logout, es, acr, flag, rev, raw, dumped
    rp.fetch_jwks(fetch, "https://op.example.com/jwks", "https://op.example.com")
    cache = rp.JwksCache(
        reqwest,
        "https://op.example.com/jwks",
        "https://op.example.com",
        default_ttl=600,
        min_ttl=30,
        max_ttl=3600,
        min_refresh_interval=10,
        fetch_timeout=5.0,
    )
    rp.JwksCache(None, "https://op.example.com/jwks", "https://op.example.com")
    dcache = rp.DiscoveryCache(
        reqwest,
        "https://op.example.com",
        default_ttl=600,
        min_ttl=30,
        max_ttl=3600,
        failure_backoff=5,
        stale_on_error=False,
        max_stale=120,
        fetch_timeout=5.0,
        allow_cross_origin_end_session=True,
    )
    rp.DiscoveryCache(None, "https://op.example.com")
    dmeta: metadata.ProviderMetadata = dcache.metadata()
    dinfo: rp.ProviderInfo = dcache.info()
    dkeys: rp.JwksCache = dcache.jwks()
    dcache.refresh()
    dissuer: str = dcache.issuer
    dbackoff: int = dcache.failure_backoff
    dtimeout: float = dcache.fetch_timeout
    del dmeta, dinfo, dkeys, dissuer, dbackoff, dtimeout
    keyset: dict[str, object] = cache.jwks()
    cache.refresh()
    cached_claims: dict[str, object] = cache.verify_id_token(
        "tok",
        "demo",
        "n",
        ["ES256"],
        leeway=30,
        max_age=300,
        acr_values=["mfa"],
        access_token="at",
        require_at_hash=True,
        authorization_code="c",
        require_c_hash=False,
        strict_hashes=True,
        trusted_additional_audiences=["https://api.example"],
    )
    direct: dict[str, object] = rp.verify_id_token(
        cache, "tok", "https://op.example.com", "demo", "n", ["ES256"], max_age=60
    )
    rp.verify_id_token(keyset, "tok", "https://op.example.com", "demo", "n", ["ES256"], leeway=5)
    del keyset, cached_claims, direct
    rp.fetch_userinfo(reqwest, "https://op.example.com/ui", "tok", "sub", "https://op.example.com")

    rp.fetch_userinfo(
        reqwest,
        None,
        "tok",
        "sub",
        "https://op.example.com",
        method="GET",
        jwks={"keys": []},
        client_id="demo",
        allowed_algorithms=["ES256"],
        trust="typed",
        typ="userinfo+jwt",
        max_age=None,
        require_exp=True,
    )
    rp.fetch_userinfo(custom, "https://op.example.com/ui", "tok", "sub", "https://op.example.com")
    rp.fetch_userinfo(
        HeadersClient(),
        "https://op.example.com/ui",
        "tok",
        "sub",
        "https://op.example.com",
        method="GET",
        trust="dedicated_keys",
    )
    rp.fetch_userinfo(
        GetWithHeadersClient(),
        "https://op.example.com/ui",
        "tok",
        "sub",
        "https://op.example.com",
        method="GET",
    )
    reqwest.get("https://op.example.com", [("Authorization", "Bearer t")])

    federation.fetch_entity_configuration(reqwest, "https://ta.example.com")
    federation.fetch_entity_configuration(custom, "https://ta.example.com")
    federation.fetch_collection(None, "https://ta.example.com/collection", "openid_provider")

    discovery.self_published_rp(reqwest, "https://rp.example.com")
    discovery.self_published_rp(custom, "https://rp.example.com")
    discovery.self_published_initiate_login_uri(None, "https://rp.example.com")

    status, body, content_type = reqwest.get("https://op.example.com")
    reveal: tuple[int, bytes, str | None] = (status, body, content_type)
    del reveal


def use_errors() -> None:
    try:
        rp.JwksCache(None, "https://x/jwks", "https://x").verify_id_token("t", "c", "n", ["ES256"])
    except pygrindvakt.UnknownKeyError as ke:
        jose: pygrindvakt.JoseError = ke
        print(jose.code, ke.status_hint)

    try:
        rp.exchange_code(
            None,
            rp.ProviderInfo("i", "a", "t"),
            rp.RpClient("c", "https://x/cb"),
            "code",
        )
    except GrindvaktError as e:
        code: str = e.code
        status: int | None = e.upstream_status
        upstream_error: str | None = e.upstream_error
        description: str | None = e.upstream_error_description
        body: str | None = e.upstream_body
        cause: BaseException | None = e.__cause__
        auth_failure: bool = e.auth_failure
        retryable: bool = e.retryable
        summary: str = e.log_summary
        del code, status, upstream_error, description, body, cause
        del auth_failure, retryable, summary
    except (AuthnError, InternalError, OAuthError) as e:
        print(e.code)


def use_bad_request() -> None:
    try:
        rp.RpClient("c", "https://x/cb", auth_method="x")
    # BadRequestError is also a ValueError: its clause must come first or the
    # ValueError clause shadows it.
    except pygrindvakt.BadRequestError as bre:
        as_value_error: ValueError = bre
        as_base: GrindvaktError = bre
        del as_value_error, as_base
    except ValueError as ve:
        other: ValueError = ve
        del other


def use_config_error() -> None:
    try:
        rp.RpClient("c", "https://x/cb", auth_method="x")
    except pygrindvakt.ConfigError as ce:
        as_value_error: ValueError = ce
        as_base: GrindvaktError = ce
        hint: int = ce.status_hint
        summary: str = ce.log_summary
        del as_value_error, as_base, hint, summary
        raise
    except GrindvaktError as ge:
        print(ge.log_summary)


def use_validators() -> None:
    # validate_issuer / validate_service_endpoint raise ConfigError;
    # validate_redirect_uri_syntax raises BadRequestError.
    rp.validate_issuer("https://op.example")
    rp.validate_redirect_uri_syntax("https://rp.example/cb")
    rp.validate_service_endpoint("token_endpoint", "https://op.example/token")
    rp.validate_service_endpoint("token_endpoint", "https://op.example/token", issuer="https://op.example")
    rp.validate_service_endpoint(
        "token_endpoint", "http://localhost:8080/token", "http://localhost:8080", allow_loopback_http=True
    )
    cap: int = rp.MAX_ID_TOKEN_LEEWAY
    algs: list[str] = rp.asymmetric_algorithms()
    digest: str = jwt.oidc_token_hash("RS256", "token")
    supported: bool = jwt.supports_oidc_token_hash("RS256")
    del cap, algs, digest, supported


def use_authorization_response(req: pygrindvakt.http.HttpRequestData) -> None:
    r: rp.AuthorizationResponse = rp.parse_authorization_response(req)
    rp.parse_authorization_response([("code", "c"), ("state", "s")], response_mode="fragment")
    rp.parse_authorization_response({"code": ["c"]}, response_mode="form_post", accept_jarm=True)
    rp.parse_authorization_response({"code": ("c",)})
    req.query = [("code", "c")]
    req.form = [("code", "c")]
    req.query = {"code": "c"}
    req.form = {"code": "c"}
    # A plain dict[str, str] must not type-check (a str is a Sequence[str]).
    plain: dict[str, str] = {"code": "c"}
    rp.parse_authorization_response(plain)  # type: ignore[arg-type]
    v: rp.AuthorizationResponse = r.verify_jarm(
        {"keys": []},
        issuer="https://op.example",
        client_id="c",
        allowed_algorithms=rp.JARM_ASYMMETRIC_ALGORITHMS,
        trust="dedicated_keys",
        leeway=5,
    )
    r.verify_jarm({"keys": []}, issuer="i", client_id="c", allowed_algorithms=["ES256"], typ=rp.JARM_TYP)
    jv: bool = v.jarm_verified
    jt: tuple[str, ...] = rp.JARM_ASYMMETRIC_ALGORITHMS
    code: str | None = r.code
    state: str | None = r.state
    error: str | None = r.error
    desc: str | None = r.error_description_safe
    uri: str | None = r.error_uri
    iss: str | None = r.iss
    jarm: str | None = r.response
    mode: str = r.response_mode
    del jv, jt
    flags: tuple[bool, bool] = (r.is_error, r.error_known)
    ok: bool = r.matches_iss("https://op.example", required=False)
    st_ok: bool = r.matches_state("expected-state")
    st_opt: bool = r.matches_state("expected-state", required=False)
    del code, state, error, desc, uri, iss, jarm, mode, flags, ok, st_ok, st_opt


def use_helpers(unknown: object, md: metadata.ProviderMetadata) -> None:
    info = rp.ProviderInfo.from_metadata(md)
    me = rp.RpClient("demo", "https://rp.example.com/cb", client_secret="s")
    res: rp.BeginResult = rp.begin(info, me)
    begin_url: str = res.url
    begin_state: str = res.state
    begin_nonce: str = res.nonce
    begin_verifier: str | None = res.code_verifier
    as_tuple: tuple[str, str, str, str | None] = res
    url, state, nonce, verifier = res
    del begin_url, begin_state, begin_nonce, begin_verifier, as_tuple, url, state, nonce, verifier

    ts: rp.TokenSet = rp.exchange_code(None, info, me, "code")
    refresh: str | None = ts.refresh_token
    expires: int | None = ts.expires_in
    scope: str | None = ts.scope
    del refresh, expires, scope

    auds: list[str] = rp.claims_audiences({"aud": "a"})
    del auds

    embedded: metadata.ProviderMetadata | None = info.metadata
    del embedded

    problems: list[str] = rp.check_rp_compatibility(info)
    rp.check_rp_compatibility(md)
    rp.check_rp_compatibility(
        info,
        client=me,
        pkce=True,
        algorithms=["ES256"],
        scopes=("openid", "email"),
        acr_values=["urn:x"],
        shared_secret_keys=True,
    )
    rp.check_rp_compatibility(
        md, client=None, pkce=None, algorithms=None, scopes=None, acr_values=None, shared_secret_keys=False
    )
    del problems

    ok: bool = pygrindvakt.http.supports_get_with_headers(unknown)
    pygrindvakt.http.supports_get_with_headers(None)
    if pygrindvakt.http.supports_get_with_headers(unknown):
        rp.fetch_userinfo(
            unknown,
            "https://op.example.com/ui",
            "tok",
            "sub",
            "https://op.example.com",
            method="GET",
        )
    del ok


def use_authorization_response_iss(
    md: metadata.ProviderMetadata,
    key: keys.SigningKey,
    clients: client.InMemoryClientStore,
    codec: tokens.TokenCodec,
    req: request.AuthorizationRequest,
) -> None:
    op = provider.Provider(
        md,
        key,
        clients,
        codec,
        token_use_store=provider.InMemoryTokenUseStore(),
        authorization_response_iss=True,
    )
    resp: pygrindvakt.http.Response = op.authorization_error_redirect(req, OAuthError("access_denied", state=req.state))
    del resp


def use_testing(op: provider.Provider, key: keys.SigningKey) -> None:
    """``pygrindvakt.testing`` is type-checked here, so it is covered by ``--strict``."""
    route: testing.FetchResult = (200, b"{}", "application/json", (("Cache-Control", "max-age=60"),))

    def dynamic(req: testing.RecordedRequest) -> testing.FetchResult:
        return 200, req.url.encode(), None, ()

    static = testing.StaticHttpClient(
        {"https://a/x": route, ("POST", "https://a/y"): dynamic}, default=(500, b"", None, ())
    )
    routes_a: dict[str, testing.FetchResult] = {"https://a/a": route}
    routes_b: dict[tuple[str, str], testing.FetchResult] = {("GET", "https://a/b"): route}
    routes_c: dict[str | tuple[str, str], testing.FetchResult] = {"https://a/c": route, ("GET", "https://a/d"): route}
    routes_d: dict[str, Callable[[testing.RecordedRequest], testing.FetchResult]] = {"https://a/e": dynamic}
    for routes in (testing.StaticHttpClient(routes_a), testing.StaticHttpClient(routes_b)):
        rp.discover(routes, "https://op.example.com")
    testing.StaticHttpClient(routes_c, default=(500, b"", None))
    testing.StaticHttpClient(routes_d)
    from_json = testing.StaticHttpClient.from_json({"https://a/z": {"k": 1}})
    testing.StaticHttpClient.from_json({"https://a/z": {"k": 1}}, cache_control=None)
    bridge = testing.ProviderHttpClient(op, "https://op.example.com", token_path="/t", jwks_path="/j")
    testing.ProviderHttpClient(op, "https://op.example.com", cache_control=None)
    testing.ProviderHttpClient(op, "https://op.example.com", cache_control="max-age=60")
    rp.discover(static, "https://op.example.com")
    rp.discover(from_json, "https://op.example.com")
    rp.discover(bridge, "https://op.example.com")
    rp.fetch_userinfo(bridge, "https://op.example.com/userinfo", "tok", "sub", "https://op.example.com", method="GET")
    rp.fetch_userinfo(static, "https://a/x", "tok", "sub", "https://op.example.com", method="GET")
    recorded: list[testing.RecordedRequest] = static.calls + bridge.calls
    forms: list[list[tuple[str, str]]] = bridge.forms
    first: testing.RecordedRequest = recorded[0]
    method: str = first.method
    form: tuple[tuple[str, str], ...] | None = first.form
    hdrs: tuple[tuple[str, str], ...] = first.headers
    authz: str | None = first.header("authorization")
    del forms, method, form, hdrs, authz
    token: str = testing.mint_id_token(
        key,
        issuer="https://op.example.com",
        client_id="demo",
        sub="bob",
        nonce="n",
        access_token="at",
        code="c",
        lifetime=60,
        iat=1,
        extra={"acr": "x", "azp": "demo", "auth_time": 1, "jti": "j"},
    )
    testing.mint_id_token(key, issuer="https://op.example.com", client_id="demo")
    del token
