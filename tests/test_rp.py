"""Tests for ``pygrindvakt.rp`` - the relying-party side of OIDC.

An in-process ``Provider`` plays the upstream OP; a ``testing.ProviderHttpClient`` routes
the RP's outbound requests straight into it, so the full code flow
(discovery -> authorization -> code exchange -> id_token -> userinfo) runs
without any network.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
import threading
import time
import warnings
from urllib.parse import parse_qs, parse_qsl, urlsplit

import pytest
from pygrindvakt import (
    AuthnError,
    BadRequestError,
    ConfigError,
    CryptoError,
    GrindvaktError,
    InternalError,
    JoseError,
    OAuthError,
    client,
    jwt,
    keys,
    metadata,
    pkce,
    provider,
    request,
    rp,
    tokens,
    util,
)
from pygrindvakt import http as pyhttp
from pygrindvakt.testing import ProviderHttpClient, StaticHttpClient

ISSUER = "https://op.example.com"
CLIENT_ID = "demo"
CLIENT_SECRET = "s3cret"
REDIRECT_URI = "https://rp.example.com/cb"


ALT_REDIRECT_URI = "https://rp.example.com/alt-cb"


class RaisingHttpClient:
    """An ``HttpClient`` whose every request raises."""

    def get(self, url):
        raise RuntimeError("boom: network is down")

    def post_form(self, url, form, headers):
        raise RuntimeError("boom: network is down")


@pytest.fixture
def op_key():
    jwk = keys.generate_ec_jwk("P-256")
    return keys.signing_key_from_jwk(jwk, alg="ES256", kid="op-1")


@pytest.fixture
def op(op_key):
    md = metadata.ProviderMetadata(ISSUER)
    c = client.Client(
        CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_uris=[REDIRECT_URI, ALT_REDIRECT_URI],
    )
    return provider.Provider(
        md,
        op_key,
        client.InMemoryClientStore([c]),
        tokens.TokenCodec("op-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )


@pytest.fixture
def http(op):
    return ProviderHttpClient(op, ISSUER)


@pytest.fixture
def prov(http):
    return rp.ProviderInfo.from_metadata(rp.discover(http, ISSUER))


@pytest.fixture
def rpc():
    return rp.RpClient(
        CLIENT_ID,
        REDIRECT_URI,
        client_secret=CLIENT_SECRET,
        redirect_uris=[ALT_REDIRECT_URI],
    )


@pytest.fixture
def rp_key():
    jwk = keys.generate_ec_jwk("P-256")
    return keys.signing_key_from_jwk(jwk, alg="ES256", kid="rp-1")


def run_authorization(op, prov, rpc, state, nonce, verifier, sub="alice", claims=None):
    """Drive the OP side of the flow and return the authorization code."""
    url = rp.authorization_url(prov, rpc, state, nonce, pkce.s256_challenge(verifier))
    params = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
    req = request.AuthorizationRequest.from_params(list(params.items()))
    op.validate_authorization_request(req)
    resp = op.authorization_redirect(req, sub, claims or {"email": ["a@b"]})
    assert resp.status in (302, 303)
    location = resp.header("location")
    assert location.startswith(REDIRECT_URI)
    q = parse_qs(urlsplit(location).query)
    assert q["state"] == [state]
    return q["code"][0]


# --- discovery ----------------------------------------------------------------


def test_discover_returns_metadata_for_issuer(http):
    """``discover`` fetches the discovery document and returns ProviderMetadata."""
    md = rp.discover(http, ISSUER)
    assert isinstance(md, metadata.ProviderMetadata)
    assert md.issuer == ISSUER
    assert [(r.method, r.url) for r in http.calls] == [("GET", f"{ISSUER}/.well-known/openid-configuration")]


def test_discover_with_trailing_slash(http):
    """Issuer identifiers differing by a trailing slash are not conflated."""
    with pytest.raises(AuthnError):
        rp.discover(http, ISSUER + "/")


def test_discover_rejects_plain_http_before_fetching(http):
    """Plain-http issuers (non-loopback) are refused without any request."""
    with pytest.raises(GrindvaktError):
        rp.discover(http, "http://op.example.com")
    assert http.calls == []


def test_discover_fails_closed_when_http_client_raises(unraisable):
    """A raising HttpClient surfaces as InternalError carrying the message.

    The adapter's traceback is also routed through ``sys.unraisablehook`` so
    operators can see it; the ``unraisable`` fixture records and checks it.
    """
    with pytest.raises(InternalError, match="network is down"):
        rp.discover(RaisingHttpClient(), ISSUER)
    unraisable.expect(RuntimeError, "network is down", count=1, adapter=RaisingHttpClient)


def test_discover_rejects_issuer_mismatch(op):
    """The issuer in the returned document must match the requested one."""

    doc = op.discovery_document()
    doc["issuer"] = "https://evil.example.com"
    liar = StaticHttpClient.from_json({f"{ISSUER}/.well-known/openid-configuration": doc})
    with pytest.raises(AuthnError, match="does not match"):
        rp.discover(liar, ISSUER)


def test_fetch_jwks_returns_one_key(http, prov):
    """``fetch_jwks`` returns the JWKS dict with the OP's single signing key."""
    jwks = rp.fetch_jwks(http, prov.jwks_uri, prov.issuer)
    assert isinstance(jwks, dict)
    assert len(jwks["keys"]) == 1
    assert jwks["keys"][0]["kid"] == "op-1"
    assert "d" not in jwks["keys"][0]


# --- ProviderInfo -----------------------------------------------------------------


def test_provider_info_from_metadata(op):
    """``from_metadata`` copies the endpoints, including userinfo and jwks."""
    md = op.metadata
    p = rp.ProviderInfo.from_metadata(md)
    assert p.issuer == ISSUER
    assert p.authorization_endpoint == md.authorization_endpoint
    assert p.token_endpoint == md.token_endpoint
    assert p.userinfo_endpoint == md.userinfo_endpoint
    assert p.jwks_uri == md.jwks_uri
    assert "ProviderInfo(" in repr(p) and ISSUER in repr(p)


def test_provider_info_constructor_defaults():
    """Optional endpoints default to None."""
    p = rp.ProviderInfo(ISSUER, f"{ISSUER}/authz", f"{ISSUER}/token")
    assert p.userinfo_endpoint is None
    assert p.jwks_uri is None
    assert "userinfo_endpoint=None" in repr(p)
    p2 = rp.ProviderInfo(ISSUER, f"{ISSUER}/authz", f"{ISSUER}/token", jwks_uri=f"{ISSUER}/jwks")
    assert p2.jwks_uri == f"{ISSUER}/jwks"


# --- RpClient -------------------------------------------------------------------


def test_rp_client_defaults():
    """Default scope, auth_method inferred from the presence of a secret."""
    c = rp.RpClient(CLIENT_ID, REDIRECT_URI)
    assert c.client_id == CLIENT_ID
    assert c.redirect_uri == REDIRECT_URI
    assert c.scope == "openid profile email"
    assert c.auth_method == "none"
    c2 = rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret=CLIENT_SECRET, scope="openid")
    assert c2.auth_method == "client_secret_basic"
    assert c2.scope == "openid"


def test_rp_client_explicit_methods(rp_key):
    """Every explicit auth_method is accepted with its matching credential."""
    assert (
        rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret="x", auth_method="client_secret_post").auth_method
        == "client_secret_post"
    )
    assert (
        rp.RpClient(CLIENT_ID, REDIRECT_URI, auth_method="private_key_jwt", signing_key=rp_key).auth_method
        == "private_key_jwt"
    )
    assert rp.RpClient(CLIENT_ID, REDIRECT_URI, auth_method="none").auth_method == "none"


def test_rp_client_repr_hides_secret():
    """The secret never appears in repr()."""
    c = rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret=CLIENT_SECRET)
    r = repr(c)
    assert CLIENT_SECRET not in r
    assert "client_secret_basic" in r and CLIENT_ID in r


@pytest.mark.parametrize(
    "kwargs",
    [
        {"auth_method": "private_key_jwt"},
        {"auth_method": "client_secret_basic"},
        {"auth_method": "client_secret_post"},
        {"auth_method": "bogus"},
        {"auth_method": "none", "client_secret": "x"},
        {"client_secret": ""},
    ],
)
def test_rp_client_rejects_inconsistent_combinations(kwargs):
    """Inconsistent method / credential combinations raise ValueError."""
    with pytest.raises(ValueError):
        rp.RpClient(CLIENT_ID, REDIRECT_URI, **kwargs)


def test_rp_client_rejects_unused_signing_key(rp_key):
    """A signing_key that the resolved method would ignore is rejected."""
    with pytest.raises(ValueError, match="private_key_jwt"):
        rp.RpClient(CLIENT_ID, REDIRECT_URI, signing_key=rp_key)
    with pytest.raises(ValueError):
        rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret="x", signing_key=rp_key)
    with pytest.raises(ValueError):
        rp.RpClient(
            CLIENT_ID,
            REDIRECT_URI,
            auth_method="private_key_jwt",
            signing_key=rp_key,
            client_secret="x",
        )


# --- authorization_url ------------------------------------------------------------


def test_authorization_url_contains_parameters(prov, rpc):
    """state, nonce, PKCE challenge and extra params are all present."""
    challenge = pkce.s256_challenge("v" * 43)
    url = rp.authorization_url(prov, rpc, "st-1", "n-1", challenge, extra={"prompt": "login"})
    assert url.startswith(prov.authorization_endpoint + "?")
    q = parse_qs(urlsplit(url).query)
    assert q["response_type"] == ["code"]
    assert q["client_id"] == [CLIENT_ID]
    assert q["redirect_uri"] == [REDIRECT_URI]
    assert q["scope"] == ["openid profile email"]
    assert q["state"] == ["st-1"]
    assert q["nonce"] == ["n-1"]
    assert q["code_challenge"] == [challenge]
    assert q["code_challenge_method"] == ["S256"]
    assert q["prompt"] == ["login"]


def test_authorization_url_extra_as_list_and_no_pkce(prov, rpc):
    """extra may be a list of tuples; without a challenge no PKCE params appear."""
    url = rp.authorization_url(prov, rpc, "st", "n", extra=[("acr_values", "mfa"), ("prompt", "none")])
    q = parse_qs(urlsplit(url).query)
    assert q["acr_values"] == ["mfa"]
    assert q["prompt"] == ["none"]
    assert "code_challenge" not in q
    with pytest.raises((ValueError, TypeError)):
        rp.authorization_url(prov, rpc, "st", "n", extra="prompt=login")


def test_authorization_url_appends_to_existing_query(rpc):
    """An authorization endpoint that already has a query gets '&'."""
    p = rp.ProviderInfo(ISSUER, f"{ISSUER}/authz?tenant=x", f"{ISSUER}/token")
    url = rp.authorization_url(p, rpc, "st", "n")
    assert url.startswith(f"{ISSUER}/authz?tenant=x&response_type=code")


def test_provider_info_rejects_unsafe_endpoints_and_reserved_query(rpc):
    for endpoint in [
        "http://example.com/token",
        "file:///tmp/token",
        "https://u:p@example.com/token",
        "https://example.com/token#fragment",
        "http://127.0.0.1:8000/token",
    ]:
        with pytest.raises(GrindvaktError):
            rp.ProviderInfo(ISSUER, f"{ISSUER}/authorization", endpoint)
    with pytest.raises(GrindvaktError, match="library-controlled"):
        rp.ProviderInfo(ISSUER, f"{ISSUER}/authorization?client_id=attacker", f"{ISSUER}/token")
    # Separate HTTPS endpoint origins remain legitimate. Loopback HTTP is a
    # development exception only when the issuer is itself loopback HTTP.
    rp.ProviderInfo(
        ISSUER,
        "https://login.example.net/authorization",
        "https://tokens.example.net/token",
    )
    rp.ProviderInfo(
        "http://127.0.0.1:8000",
        "http://127.0.0.1:8000/authorization",
        "http://localhost:8000/token",
    )


def test_direct_endpoint_fetches_bind_loopback_http_to_issuer():
    """A remote issuer cannot send credential-bearing fetches to loopback."""
    with pytest.raises(GrindvaktError, match="absolute https URL"):
        rp.fetch_jwks(
            RaisingHttpClient(),
            "http://127.0.0.1:8000/jwks",
            "https://remote.example",
        )
    with pytest.raises(GrindvaktError, match="absolute https URL"):
        rp.fetch_userinfo(
            RaisingHttpClient(),
            "http://127.0.0.1:8000/userinfo",
            "access-token",
            "alice",
            "https://remote.example",
        )


def test_public_rp_requires_pkce_at_every_boundary(prov, rp_key):
    public = rp.RpClient("public", REDIRECT_URI, auth_method="none")
    with pytest.raises(GrindvaktError, match="PKCE"):
        rp.authorization_url(prov, public, "state", "nonce")
    with pytest.raises(GrindvaktError, match="PKCE"):
        rp.signed_request_object(prov, public, rp_key, "state", "nonce")
    with pytest.raises(GrindvaktError, match="PKCE"):
        rp.exchange_code(RaisingHttpClient(), prov, public, "code")


def test_authorization_url_rejects_reserved_and_ambiguous_extras(prov, rpc):
    with pytest.raises(GrindvaktError, match="library-controlled"):
        rp.authorization_url(prov, rpc, "state", "nonce", extra={"redirect_uri": "https://evil/cb"})
    with pytest.raises(GrindvaktError, match="duplicate"):
        rp.authorization_url(prov, rpc, "state", "nonce", extra=[("prompt", "login"), ("prompt", "none")])
    configured = rp.ProviderInfo(ISSUER, f"{ISSUER}/authorization?tenant=configured", f"{ISSUER}/token")
    with pytest.raises(GrindvaktError, match="duplicate"):
        rp.authorization_url(configured, rpc, "state", "nonce", extra={"tenant": "override"})
    url = rp.authorization_url(
        prov,
        rpc,
        "state",
        "nonce",
        extra=[("resource", "https://api-1"), ("resource", "https://api-2")],
    )
    assert len(parse_qs(urlsplit(url).query)["resource"]) == 2


# --- redirect_uri override ----------------------------------------------------------


def test_redirect_uri_override_in_authorization_url_and_jar(prov, rpc, rp_key):
    url = rp.authorization_url(prov, rpc, "st", "n", redirect_uri=ALT_REDIRECT_URI)
    assert parse_qs(urlsplit(url).query)["redirect_uri"] == [ALT_REDIRECT_URI]
    assert rpc.redirect_uri == REDIRECT_URI  # the client itself is unchanged
    jar = rp.signed_request_object(prov, rpc, rp_key, "st", "n", redirect_uri=ALT_REDIRECT_URI)
    import base64

    claims = json.loads(base64.urlsafe_b64decode(jar.split(".")[1] + "=="))
    assert claims["redirect_uri"] == ALT_REDIRECT_URI


def test_redirect_uri_override_reaches_token_request(op, http, prov, rpc):
    state, nonce, verifier = (
        util.random_token(),
        util.random_token(),
        util.random_token(48),
    )
    url = rp.authorization_url(
        prov,
        rpc,
        state,
        nonce,
        pkce.s256_challenge(verifier),
        redirect_uri=ALT_REDIRECT_URI,
    )
    req = request.AuthorizationRequest.from_params([(k, v[0]) for k, v in parse_qs(urlsplit(url).query).items()])
    op.validate_authorization_request(req)
    resp = op.authorization_redirect(req, "alice", {"email": ["a@b"]})
    code = parse_qs(urlsplit(resp.header("location")).query)["code"][0]
    ts = rp.exchange_code(http, prov, rpc, code, verifier, redirect_uri=ALT_REDIRECT_URI)
    assert ts.id_token
    assert ("redirect_uri", ALT_REDIRECT_URI) in http.forms[-1]
    assert ("redirect_uri", REDIRECT_URI) not in http.forms[-1]


def _all_overrides(prov, client, rp_key, uri):
    """Run every per-call override entry point; yield one callable each."""
    return [
        lambda: rp.authorization_url(prov, client, "st", "n", redirect_uri=uri),
        lambda: rp.signed_request_object(prov, client, rp_key, "st", "n", redirect_uri=uri),
        lambda: rp.begin(prov, client, redirect_uri=uri),
        lambda: rp.exchange_code(RaisingHttpClient(), prov, client, "code", "v" * 43, redirect_uri=uri),
    ]


@pytest.mark.parametrize(
    "bad",
    [
        "https://evil.example/steal",
        "http://evil.example/cb",
        REDIRECT_URI + "/",
        REDIRECT_URI.upper(),
        ALT_REDIRECT_URI + "/",
        ALT_REDIRECT_URI + "?x=1",
        ALT_REDIRECT_URI.replace("rp.example.com", "rp.example.com:8443"),
        ALT_REDIRECT_URI.replace("https://rp", "https://RP"),
    ],
)
def test_unregistered_redirect_uri_override_rejected(prov, rpc, rp_key, bad):
    for call in _all_overrides(prov, rpc, rp_key, bad):
        with pytest.raises(BadRequestError, match="redirect_uris"):
            call()


def test_unregistered_override_error_names_escape_hatch(prov, rpc):
    with pytest.raises(BadRequestError, match="allow_unregistered_redirect_uri"):
        rp.authorization_url(prov, rpc, "st", "n", redirect_uri="https://evil.example/steal")


def test_configured_redirect_uri_override_is_noop(prov, rpc, rp_key):
    plain = rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret=CLIENT_SECRET)
    url = rp.authorization_url(prov, plain, "st", "n", redirect_uri=REDIRECT_URI)
    assert parse_qs(urlsplit(url).query)["redirect_uri"] == [REDIRECT_URI]
    rp.signed_request_object(prov, plain, rp_key, "st", "n", redirect_uri=REDIRECT_URI)
    rp.begin(prov, plain, redirect_uri=REDIRECT_URI)


def test_redirect_uris_properties_and_repr():
    c = rp.RpClient("c", REDIRECT_URI, redirect_uris=[ALT_REDIRECT_URI])
    assert c.redirect_uris == (ALT_REDIRECT_URI,)
    assert c.allow_unregistered_redirect_uri is False
    assert "redirect_uris=" in repr(c)
    d = rp.RpClient("c", REDIRECT_URI, allow_unregistered_redirect_uri=True)
    assert d.redirect_uris == ()
    assert d.allow_unregistered_redirect_uri is True
    assert "allow_unregistered_redirect_uri=True" in repr(d)


def test_allow_unregistered_redirect_uri_accepts_valid_https(prov, rp_key):
    c = rp.RpClient(
        CLIENT_ID,
        REDIRECT_URI,
        client_secret=CLIENT_SECRET,
        allow_unregistered_redirect_uri=True,
    )
    uri = "https://other.example/dyn"
    url = rp.authorization_url(prov, c, "st", "n", redirect_uri=uri)
    assert parse_qs(urlsplit(url).query)["redirect_uri"] == [uri]
    rp.signed_request_object(prov, c, rp_key, "st", "n", redirect_uri=uri)
    rp.begin(prov, c, redirect_uri=uri)
    for bad in (
        "https://other.example/dyn#frag",
        "http://other.example/cb",
        "/relative",
        "",
    ):
        for call in _all_overrides(prov, c, rp_key, bad):
            with pytest.raises(BadRequestError):
                call()
    url = rp.authorization_url(prov, c, "st", "n", redirect_uri="http://127.0.0.1:8080/cb")
    assert "127.0.0.1" in url


def test_loopback_http_registered_override_accepted(prov):
    c = rp.RpClient(
        CLIENT_ID,
        REDIRECT_URI,
        client_secret=CLIENT_SECRET,
        redirect_uris=[
            "http://localhost:8080/cb",
            "http://[::1]:9/cb",
            "com.example.app:/oauth2redirect",
        ],
    )
    for uri in c.redirect_uris:
        url = rp.authorization_url(prov, c, "st", "n", redirect_uri=uri)
        assert parse_qs(urlsplit(url).query)["redirect_uri"] == [uri]


@pytest.mark.parametrize(
    "bad",
    [
        "https://rp.example.com/cb#frag",
        "/relative",
        "",
        "http://rp.example.com/cb",
        "http://10.0.0.1/cb",
    ],
)
def test_redirect_uris_validated_at_construction(bad):
    with pytest.raises(GrindvaktError):
        rp.RpClient(CLIENT_ID, REDIRECT_URI, redirect_uris=[bad])


@pytest.mark.parametrize("bad", ["https://rp.example.com/cb#frag", "/relative", ""])
def test_redirect_uri_override_rejected(prov, rpc, rp_key, bad):
    with pytest.raises(BadRequestError):
        rp.authorization_url(prov, rpc, "st", "n", redirect_uri=bad)
    with pytest.raises(BadRequestError):
        rp.signed_request_object(prov, rpc, rp_key, "st", "n", redirect_uri=bad)
    with pytest.raises(BadRequestError):
        rp.exchange_code(RaisingHttpClient(), prov, rpc, "code", "v" * 43, redirect_uri=bad)
    with pytest.raises(BadRequestError):
        rp.begin(prov, rpc, redirect_uri=bad)


# --- begin ----------------------------------------------------------------------------


def test_begin_returns_url_state_nonce_verifier(prov, rpc):
    url, state, nonce, verifier = rp.begin(prov, rpc)
    q = parse_qs(urlsplit(url).query)
    assert q["state"] == [state]
    assert q["nonce"] == [nonce]
    assert q["code_challenge_method"] == ["S256"]
    assert q["code_challenge"] == [pkce.s256_challenge(verifier)]
    assert pkce.verify(verifier, q["code_challenge"][0], "S256")
    assert len(verifier) == 64
    assert len(state) == len(nonce) == 43


def test_begin_values_are_fresh(prov, rpc):
    a = rp.begin(prov, rpc)
    b = rp.begin(prov, rpc)
    for i in (1, 2, 3):
        assert a[i] != b[i]


def test_begin_extra_and_override(prov, rpc):
    url, *_ = rp.begin(prov, rpc, extra={"prompt": "login"}, redirect_uri=ALT_REDIRECT_URI)
    q = parse_qs(urlsplit(url).query)
    assert q["prompt"] == ["login"]
    assert q["redirect_uri"] == [ALT_REDIRECT_URI]


def test_begin_pkce_false(prov, rpc):
    url, _, _, verifier = rp.begin(prov, rpc, pkce=False)
    assert verifier is None
    assert "code_challenge" not in parse_qs(urlsplit(url).query)


def test_begin_pkce_false_refused_for_public_client(prov):
    public = rp.RpClient("public", REDIRECT_URI, auth_method="none")
    with pytest.raises(ConfigError, match="PKCE"):
        rp.begin(prov, public, pkce=False)
    url, *_ = rp.begin(prov, public)
    assert "code_challenge" in parse_qs(urlsplit(url).query)


def test_begin_with_request_object(prov, rpc, rp_key):
    url, *_ = rp.begin(prov, rpc, request_object_key=rp_key)
    q = parse_qs(urlsplit(url).query)
    assert q["request"][0].count(".") == 2


def test_begin_then_exchange_code_flow(op, http, prov, rpc):
    url, state, nonce, verifier = rp.begin(prov, rpc)
    req = request.AuthorizationRequest.from_params([(k, v[0]) for k, v in parse_qs(urlsplit(url).query).items()])
    op.validate_authorization_request(req)
    resp = op.authorization_redirect(req, "alice", {"email": ["a@b"]})
    q = parse_qs(urlsplit(resp.header("location")).query)
    assert q["state"] == [state]
    ts = rp.exchange_code(http, prov, rpc, q["code"][0], verifier)
    jwks = rp.fetch_jwks(http, prov.jwks_uri, prov.issuer)
    claims = rp.verify_id_token(jwks, ts.id_token, ISSUER, CLIENT_ID, nonce, ["ES256"])
    assert claims["sub"] == "alice"


# --- full code flow -----------------------------------------------------------------


def test_full_code_flow(op, http, prov, rpc):
    """authorization_url -> OP -> exchange_code -> verify_id_token -> userinfo."""
    state, nonce, verifier = (
        util.random_token(),
        util.random_token(),
        util.random_token(48),
    )
    code = run_authorization(op, prov, rpc, state, nonce, verifier)

    ts = rp.exchange_code(http, prov, rpc, code, verifier)
    assert isinstance(ts, rp.TokenSet)
    assert ts.access_token and ts.id_token
    assert ts.token_type.lower() == "bearer"
    assert ts.raw["access_token"] == ts.access_token
    assert "expires_in" in ts.raw
    assert ts.access_token not in repr(ts) and ts.id_token not in repr(ts)
    assert 'token_type="' in repr(ts)

    jwks = rp.fetch_jwks(http, prov.jwks_uri, prov.issuer)
    claims = rp.verify_id_token(jwks, ts.id_token, ISSUER, CLIENT_ID, nonce, ["ES256"])
    assert claims["sub"] == "alice"
    assert claims["iss"] == ISSUER
    assert claims["nonce"] == nonce
    assert claims["aud"] == CLIENT_ID or CLIENT_ID in claims["aud"]

    info = rp.fetch_userinfo(http, prov.userinfo_endpoint, ts.access_token, claims["sub"], prov.issuer)
    assert info["sub"] == "alice"
    assert info["email"] == "a@b"


def test_exchange_code_with_client_secret_post(op, prov):
    """client_secret_post authenticates via the form body (OP registered for it)."""
    c = client.Client(
        CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_uris=[REDIRECT_URI],
        token_endpoint_auth_method="client_secret_post",
    )
    op2 = provider.Provider(
        op.metadata,
        op.signing_key,
        client.InMemoryClientStore([c]),
        tokens.TokenCodec("op-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )
    rpc = rp.RpClient(
        CLIENT_ID,
        REDIRECT_URI,
        client_secret=CLIENT_SECRET,
        auth_method="client_secret_post",
    )
    verifier = util.random_token(48)
    code = run_authorization(op2, prov, rpc, "st", "n", verifier)
    ts = rp.exchange_code(ProviderHttpClient(op2, ISSUER), prov, rpc, code, verifier)
    assert ts.id_token


def test_exchange_code_method_mismatch_is_refused(op, http, prov):
    """An RP using client_secret_post against a client_secret_basic registration fails."""
    rpc = rp.RpClient(
        CLIENT_ID,
        REDIRECT_URI,
        client_secret=CLIENT_SECRET,
        auth_method="client_secret_post",
    )
    verifier = util.random_token(48)
    code = run_authorization(op, prov, rpc, "st", "n", verifier)
    with pytest.raises(AuthnError, match="token endpoint returned 401") as ei:
        rp.exchange_code(http, prov, rpc, code, verifier)
    assert ei.value.code == "invalid_client"
    assert ei.value.upstream_status == 401


def test_exchange_code_wrong_secret_raises_authn(op, http, prov):
    """A rejected token request surfaces as AuthnError (fail closed)."""
    good = rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret=CLIENT_SECRET)
    bad = rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret="wrong")
    verifier = util.random_token(48)
    code = run_authorization(op, prov, good, "st", "n", verifier)
    with pytest.raises(AuthnError, match="token endpoint returned"):
        rp.exchange_code(http, prov, bad, code, verifier)


def test_exchange_code_wrong_verifier_raises(op, http, prov, rpc):
    """A PKCE verifier mismatch is rejected by the OP and raised here."""
    code = run_authorization(op, prov, rpc, "st", "n", util.random_token(48))
    with pytest.raises(AuthnError):
        rp.exchange_code(http, prov, rpc, code, util.random_token(48))


# --- verify_id_token ----------------------------------------------------------------


@pytest.fixture
def issued(op, http, prov, rpc):
    """An (id_token, jwks, nonce) triple from a completed flow."""
    nonce, verifier = util.random_token(), util.random_token(48)
    code = run_authorization(op, prov, rpc, "st", nonce, verifier)
    ts = rp.exchange_code(http, prov, rpc, code, verifier)
    return ts.id_token, rp.fetch_jwks(http, prov.jwks_uri, prov.issuer), nonce


def test_verify_id_token_nonce_mismatch(issued):
    """A wrong expected nonce is rejected."""
    id_token, jwks, _nonce = issued
    with pytest.raises(GrindvaktError, match="nonce"):
        rp.verify_id_token(jwks, id_token, ISSUER, CLIENT_ID, "not-the-nonce", ["ES256"])


def test_verify_id_token_wrong_audience_and_issuer(issued):
    """Audience and issuer are enforced."""
    id_token, jwks, nonce = issued
    with pytest.raises(GrindvaktError):
        rp.verify_id_token(jwks, id_token, ISSUER, "other-client", nonce, ["ES256"])
    with pytest.raises(GrindvaktError):
        rp.verify_id_token(jwks, id_token, "https://other.example.com", CLIENT_ID, nonce, ["ES256"])


def test_verify_id_token_wrong_key(issued):
    """A JWKS that does not contain the signing key is rejected."""
    id_token, _jwks, nonce = issued
    other = keys.signing_key_from_jwk(keys.generate_ec_jwk("P-256"), alg="ES256", kid="op-1")
    with pytest.raises(GrindvaktError):
        rp.verify_id_token(other.to_public_jwks(), id_token, ISSUER, CLIENT_ID, nonce, ["ES256"])


def test_verify_id_token_requires_nonce_by_default(issued):
    """expected_nonce=None without the unsafe flag raises AuthnError."""
    id_token, jwks, _nonce = issued
    with pytest.raises(AuthnError, match="expected_nonce is required"):
        rp.verify_id_token(jwks, id_token, ISSUER, CLIENT_ID, None, ["ES256"])


def test_verify_id_token_unsafe_skip_warns(issued):
    """unsafe_skip_nonce_check=True skips the check and emits a UserWarning."""
    id_token, jwks, _nonce = issued
    with pytest.warns(UserWarning, match="nonce check skipped"):
        claims = rp.verify_id_token(
            jwks,
            id_token,
            ISSUER,
            CLIENT_ID,
            None,
            ["ES256"],
            unsafe_skip_nonce_check=True,
        )
    assert claims["sub"] == "alice"


def test_verify_id_token_unsafe_flag_with_nonce_still_checks(issued):
    """The flag only matters when no nonce is given; a given nonce is enforced."""
    id_token, jwks, nonce = issued
    claims = rp.verify_id_token(
        jwks,
        id_token,
        ISSUER,
        CLIENT_ID,
        nonce,
        ["ES256"],
        unsafe_skip_nonce_check=True,
    )
    assert claims["nonce"] == nonce
    with pytest.raises(GrindvaktError, match="nonce"):
        rp.verify_id_token(
            jwks,
            id_token,
            ISSUER,
            CLIENT_ID,
            "wrong",
            ["ES256"],
            unsafe_skip_nonce_check=True,
        )


def test_verify_id_token_subject_audience_azp_and_algorithm_policy(op_key):
    now = int(time.time())
    base = {
        "iss": ISSUER,
        "sub": "alice",
        "aud": CLIENT_ID,
        "iat": now,
        "exp": now + 300,
        "nonce": "n",
    }
    jwks = op_key.to_public_jwks()

    missing_sub = {key: value for key, value in base.items() if key != "sub"}
    with pytest.raises(GrindvaktError, match="sub"):
        rp.verify_id_token(jwks, jwt.sign(op_key, missing_sub), ISSUER, CLIENT_ID, "n", ["ES256"])

    single_array = {**base, "aud": [CLIENT_ID]}
    assert rp.verify_id_token(jwks, jwt.sign(op_key, single_array), ISSUER, CLIENT_ID, "n", ["ES256"])["sub"] == "alice"
    with pytest.raises(GrindvaktError, match="azp"):
        rp.verify_id_token(
            jwks,
            jwt.sign(op_key, {**single_array, "azp": "another-client"}),
            ISSUER,
            CLIENT_ID,
            "n",
            ["ES256"],
        )

    multi = {**base, "aud": [CLIENT_ID, "https://api.example"]}
    with pytest.raises(GrindvaktError, match="untrusted audience"):
        rp.verify_id_token(jwks, jwt.sign(op_key, multi), ISSUER, CLIENT_ID, "n", ["ES256"])
    with pytest.raises(GrindvaktError, match="azp"):
        rp.verify_id_token(
            jwks,
            jwt.sign(op_key, multi),
            ISSUER,
            CLIENT_ID,
            "n",
            ["ES256"],
            ["https://api.example"],
        )
    accepted = {**multi, "azp": CLIENT_ID}
    assert (
        rp.verify_id_token(
            jwks,
            jwt.sign(op_key, accepted),
            ISSUER,
            CLIENT_ID,
            "n",
            ["ES256"],
            ["https://api.example"],
        )["sub"]
        == "alice"
    )
    with pytest.raises(GrindvaktError):
        rp.verify_id_token(jwks, jwt.sign(op_key, base), ISSUER, CLIENT_ID, "n", ["RS256"])
    with pytest.raises(GrindvaktError, match="allowed"):
        rp.verify_id_token(jwks, jwt.sign(op_key, base), ISSUER, CLIENT_ID, "n", [])


# --- userinfo -------------------------------------------------------------------


def test_fetch_userinfo_bad_token_raises(http, prov):
    """A rejected access token surfaces as AuthnError."""
    with pytest.raises(AuthnError, match="userinfo returned"):
        rp.fetch_userinfo(http, prov.userinfo_endpoint, "garbage", "expected-sub", prov.issuer)


def test_fetch_userinfo_requires_matching_subject():
    class UserInfoHttp:
        def get(self, url):
            raise AssertionError("unexpected GET")

        def post_form(self, url, form, headers):
            return (
                200,
                b'{"sub":"mallory","email":"m@example.test"}',
                "application/json",
            )

    with pytest.raises(AuthnError, match="subject"):
        rp.fetch_userinfo(UserInfoHttp(), f"{ISSUER}/userinfo", "access-token", "alice", ISSUER)


@pytest.mark.parametrize(
    "payload",
    [
        {"id_token": "i", "token_type": "Bearer"},
        {"access_token": "a", "token_type": "Bearer"},
        {"access_token": "a", "id_token": "i"},
        {"access_token": "", "id_token": "i", "token_type": "Bearer"},
    ],
)
def test_exchange_code_rejects_partial_success(payload):
    class TokenHttp:
        def get(self, url):
            raise AssertionError("unexpected GET")

        def post_form(self, url, form, headers):
            return 200, json.dumps(payload).encode(), "application/json"

    info = rp.ProviderInfo(ISSUER, f"{ISSUER}/authorization", f"{ISSUER}/token")
    confidential = rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret=CLIENT_SECRET)
    with pytest.raises(AuthnError, match="missing"):
        rp.exchange_code(TokenHttp(), info, confidential, "code")


def test_exchange_code_rejects_unknown_token_type():
    """An RP must not use an access-token scheme it does not implement."""

    class TokenHttp:
        def get(self, url):
            raise AssertionError("unexpected GET")

        def post_form(self, url, form, headers):
            payload = {"access_token": "a", "id_token": "i", "token_type": "Unknown"}
            return 200, json.dumps(payload).encode(), "application/json"

    info = rp.ProviderInfo(ISSUER, f"{ISSUER}/authorization", f"{ISSUER}/token")
    confidential = rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret=CLIENT_SECRET)
    with pytest.raises(AuthnError, match="unsupported token_type"):
        rp.exchange_code(TokenHttp(), info, confidential, "code")


# --- client assertions / request objects ----------------------------------------


def test_build_client_assertion(rp_key):
    """The assertion is a JWT with iss == sub == client_id and aud == audience."""
    aud = f"{ISSUER}/token"
    jws = rp.build_client_assertion(rp_key, CLIENT_ID, aud)
    claims = jwt.peek_claims_unverified(jws)
    assert claims["iss"] == CLIENT_ID
    assert claims["sub"] == CLIENT_ID
    assert claims["aud"] == aud
    assert claims["jti"]
    assert 0 < claims["exp"] - claims["iat"] <= 300
    assert jwt.peek_header(jws)["kid"] == "rp-1"
    v = jwt.Validation().with_issuer(CLIENT_ID).with_audience(aud).require_exp()
    assert jwt.verify_with_jwks(rp_key.to_public_jwks(), jws, v)["sub"] == CLIENT_ID


def test_private_key_jwt_client_authenticates(op, http, prov, rp_key):
    """private_key_jwt sends a client_assertion; a mismatched key is refused."""
    # Register a private_key_jwt client on the OP with the RP's public key.
    c = client.Client(
        "jwt-client",
        redirect_uris=[REDIRECT_URI],
        token_endpoint_auth_method="private_key_jwt",
        jwks=rp_key.to_public_jwks(),
    )
    op2 = provider.Provider(
        op.metadata,
        op.signing_key,
        client.InMemoryClientStore([c]),
        tokens.TokenCodec("op-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )
    http2 = ProviderHttpClient(op2, ISSUER)
    rpc = rp.RpClient("jwt-client", REDIRECT_URI, auth_method="private_key_jwt", signing_key=rp_key)
    verifier = util.random_token(48)
    code = run_authorization(op2, prov, rpc, "st", "n", verifier)
    ts = rp.exchange_code(http2, prov, rpc, code, verifier)
    assert ts.id_token

    other = keys.signing_key_from_jwk(keys.generate_ec_jwk("P-256"), alg="ES256", kid="rp-1")
    bad = rp.RpClient("jwt-client", REDIRECT_URI, auth_method="private_key_jwt", signing_key=other)
    code = run_authorization(op2, prov, rpc, "st", "n", verifier)
    with pytest.raises(AuthnError):
        rp.exchange_code(http2, prov, bad, code, verifier)


def test_signed_request_object(prov, rpc, rp_key):
    """The request object carries the authorization parameters, signed by key."""
    challenge = pkce.s256_challenge("v" * 43)
    jar = rp.signed_request_object(prov, rpc, rp_key, "st-1", "n-1", challenge)
    v = jwt.Validation().with_issuer(CLIENT_ID).with_audience(ISSUER)
    claims = jwt.verify_with_jwks(rp_key.to_public_jwks(), jar, v)
    assert claims["client_id"] == CLIENT_ID
    assert claims["redirect_uri"] == REDIRECT_URI
    assert claims["response_type"] == "code"
    assert claims["state"] == "st-1"
    assert claims["nonce"] == "n-1"
    assert claims["code_challenge"] == challenge
    assert claims["code_challenge_method"] == "S256"
    assert claims["jti"]
    plain = jwt.peek_claims_unverified(rp.signed_request_object(prov, rpc, rp_key, "st", "n"))
    assert "code_challenge" not in plain


# --- claims_to_attributes ---------------------------------------------------------


def test_claims_to_attributes_shape():
    """Strings, lists, numbers and bools map to string lists; the rest is dropped."""
    out = rp.claims_to_attributes(
        {
            "a": "x",
            "b": ["y", "z"],
            "n": 3,
            "t": True,
            "obj": {"k": "v"},
            "none": None,
            "empty": [],
        }
    )
    assert out == {"a": ["x"], "b": ["y", "z"], "n": ["3"], "t": ["true"]}
    assert rp.claims_to_attributes({}) == {}


# --- userinfo: GET, signed JWT, endpoint policy --------------------------------

UI_URL = f"{ISSUER}/userinfo"


class UserinfoRecorder:
    """Python client with header support on ``get``; records every request."""

    def __init__(self, status=200, body=b'{"sub":"alice","name":"A"}', ctype="application/json"):
        self.calls = []
        self.resp = (status, body, ctype)

    def get(self, url, headers=None):
        self.calls.append(("GET", url, headers))
        return self.resp

    def post_form(self, url, form, headers):
        self.calls.append(("POST", url, form, headers))
        return self.resp


def ui(http, **kw):
    return rp.fetch_userinfo(http, UI_URL, "tok", "alice", ISSUER, **kw)


def test_userinfo_post_default_unchanged():
    c = UserinfoRecorder()
    assert ui(c)["name"] == "A"
    assert c.calls == [("POST", UI_URL, [], [("authorization", "Bearer tok")])]


def test_userinfo_get_sends_authorization_header():
    c = UserinfoRecorder()
    assert ui(c, method="GET")["sub"] == "alice"
    assert c.calls == [("GET", UI_URL, [("authorization", "Bearer tok")])]


def test_userinfo_get_with_get_with_headers_preferred():
    class Both(UserinfoRecorder):
        def get_with_headers(self, url, headers):
            self.calls.append(("GWH", url, headers))
            return self.resp

    c = Both()
    ui(c, method="GET")
    assert c.calls == [("GWH", UI_URL, [("authorization", "Bearer tok")])]


def test_userinfo_get_with_kwargs_get():
    class Kw:
        def get(self, url, **kwargs):
            self.kw = kwargs
            return 200, b'{"sub":"alice"}', "application/json"

        def post_form(self, *a):
            raise AssertionError

    c = Kw()
    ui(c, method="GET")
    assert c.kw == {"headers": [("authorization", "Bearer tok")]}


def test_userinfo_get_client_without_header_support_is_config_error():
    from pygrindvakt import ConfigError

    class Plain:
        called = False

        def get(self, url):
            Plain.called = True
            return 200, b'{"sub":"alice"}', "application/json"

        def post_form(self, url, form, headers):
            return 200, b'{"sub":"alice"}', "application/json"

    with pytest.raises(ConfigError, match="request headers"):
        ui(Plain(), method="GET")
    assert not Plain.called  # decided up front, never call-and-fall-back
    assert ui(Plain())["sub"] == "alice"  # POST still fine


def test_userinfo_get_positional_only_or_var_positional_headers_is_unsupported():
    """`headers` must be passable by keyword; the adapter calls get(url, headers=...)."""
    from pygrindvakt import ConfigError

    class PosOnly:
        called = False

        def get(self, url, headers=None, /):
            PosOnly.called = True
            return 200, b'{"sub":"alice"}', "application/json"

        def post_form(self, *a):
            raise AssertionError

    class VarPos:
        called = False

        def get(self, url, *headers):
            VarPos.called = True
            return 200, b'{"sub":"alice"}', "application/json"

        def post_form(self, *a):
            raise AssertionError

    for cls in (PosOnly, VarPos):
        with pytest.raises(ConfigError, match="request headers"):
            ui(cls(), method="GET")
        assert not cls.called


def test_userinfo_get_keyword_only_and_var_keyword_named_headers_are_supported():
    class KwOnly:
        def get(self, url, *, headers=None):
            self.h = headers
            return 200, b'{"sub":"alice"}', "application/json"

        def post_form(self, *a):
            raise AssertionError

    class VarKwHeaders:
        def get(self, url, **headers):
            self.h = headers
            return 200, b'{"sub":"alice"}', "application/json"

        def post_form(self, *a):
            raise AssertionError

    for cls in (KwOnly, VarKwHeaders):
        c = cls()
        ui(c, method="GET")
        h = c.h["headers"] if cls is VarKwHeaders else c.h
        assert h == [("authorization", "Bearer tok")]


def test_userinfo_get_typeerror_inside_client_is_not_swallowed(unraisable):
    class Boom:
        def get(self, url, headers=None):
            raise TypeError("inside client")

        def post_form(self, *a):
            raise AssertionError

    with pytest.raises(InternalError) as e:
        ui(Boom(), method="GET")
    assert e.value.code == "transport"
    unraisable.expect(TypeError, "inside client", count=1, adapter=Boom)


def test_userinfo_invalid_method_and_trust_values():
    c = UserinfoRecorder()
    with pytest.raises(ValueError, match="method"):
        ui(c, method="PUT")
    with pytest.raises(ValueError, match="trust"):
        ui(c, trust="bogus")
    with pytest.raises(ValueError, match="requires typ"):
        ui(c, trust="typed")
    with pytest.raises(ValueError, match="only used"):
        ui(c, trust="dedicated_keys", typ="userinfo+jwt")


def test_userinfo_endpoint_none_is_config_error():
    from pygrindvakt import ConfigError

    with pytest.raises(ConfigError, match="does not advertise a userinfo_endpoint"):
        rp.fetch_userinfo(UserinfoRecorder(), None, "tok", "alice", ISSUER)


def test_userinfo_get_real_server_sends_authorization():
    import http.server as hs

    seen = []

    class H(hs.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            seen.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"sub":"alice"}')

    srv = hs.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        out = rp.fetch_userinfo(None, f"{base}/userinfo", "tok", "alice", base, method="GET")
        assert out == {"sub": "alice"} and seen == ["Bearer tok"]
    finally:
        srv.shutdown()
        srv.server_close()


def _jwt_claims(**over):
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": "alice", "aud": CLIENT_ID, "iat": now, "name": "A"}
    claims.update(over)
    return {k: v for k, v in claims.items() if v is not None}


def _signed(op_key, claims, typ=None):
    return UserinfoRecorder(body=jwt.sign(op_key, claims, typ).encode(), ctype="application/jwt")


def _verify(c, op_key, trust="dedicated_keys", typ=None, **kw):
    return ui(
        c,
        jwks=op_key.to_public_jwks(),
        client_id=CLIENT_ID,
        allowed_algorithms=["ES256"],
        trust=trust,
        typ=typ,
        **kw,
    )


def test_userinfo_signed_jwt_accepted_per_trust_mode(op_key):
    claims = _jwt_claims()
    for method in ("POST", "GET"):
        out = _verify(_signed(op_key, claims), op_key, "dedicated_keys", method=method)
        assert out["name"] == "A" and out["sub"] == "alice"
    assert _verify(_signed(op_key, claims), op_key, "untyped_shared_key_compat")["sub"] == "alice"
    typed = _signed(op_key, claims, "userinfo+jwt")
    assert _verify(typed, op_key, "typed", "userinfo+jwt")["sub"] == "alice"


def test_userinfo_typed_rejects_wrong_or_missing_typ(op_key):
    with pytest.raises(GrindvaktError):
        _verify(_signed(op_key, _jwt_claims(), "other+jwt"), op_key, "typed", "userinfo+jwt")
    with pytest.raises(GrindvaktError):
        _verify(_signed(op_key, _jwt_claims()), op_key, "typed", "userinfo+jwt")
    # typ must identify UserInfo specifically
    with pytest.raises(GrindvaktError):
        _verify(_signed(op_key, _jwt_claims(), "JWT"), op_key, "typed", "JWT")


@pytest.mark.parametrize("missing", ["jwks", "client_id", "allowed_algorithms", "trust"])
def test_userinfo_signed_jwt_fails_closed_without_verification_inputs(op_key, missing):
    kw = {
        "jwks": op_key.to_public_jwks(),
        "client_id": CLIENT_ID,
        "allowed_algorithms": ["ES256"],
        "trust": "dedicated_keys",
    }
    del kw[missing]
    with pytest.raises(AuthnError) as e:
        ui(_signed(op_key, _jwt_claims()), **kw)
    assert e.value.code == "userinfo_unverifiable"
    assert missing in str(e.value)
    # an empty algorithm list is also unverifiable
    if missing == "allowed_algorithms":
        with pytest.raises(AuthnError) as e:
            ui(
                _signed(op_key, _jwt_claims()),
                allowed_algorithms=[],
                jwks=kw["jwks"],
                client_id=CLIENT_ID,
                trust="dedicated_keys",
            )
        assert e.value.code == "userinfo_unverifiable"


def test_userinfo_signed_jwt_rejections(op_key):
    other = keys.signing_key_from_jwk(keys.generate_ec_jwk("P-256"), alg="ES256", kid="op-1")
    cases = {
        "bad signature": _signed(other, _jwt_claims()),
        "wrong iss": _signed(op_key, _jwt_claims(iss="https://evil.example")),
        "wrong aud": _signed(op_key, _jwt_claims(aud="someone-else")),
        "multi aud": _signed(op_key, _jwt_claims(aud=[CLIENT_ID, "api"])),
        "sub mismatch": _signed(op_key, _jwt_claims(sub="mallory")),
        "expired": _signed(op_key, _jwt_claims(exp=int(time.time()) - 3600)),
        "stale iat": _signed(op_key, _jwt_claims(iat=int(time.time()) - 3600)),
        "no iat": _signed(op_key, _jwt_claims(iat=None)),
        "nonce": _signed(op_key, _jwt_claims(nonce="n")),
        "at_hash": _signed(op_key, _jwt_claims(at_hash="h")),
        "c_hash": _signed(op_key, _jwt_claims(c_hash="h")),
        "id_token typ": _signed(op_key, _jwt_claims(), "id_token+jwt"),
    }
    for name, c in cases.items():
        with pytest.raises(GrindvaktError):
            _verify(c, op_key, "untyped_shared_key_compat")
            pytest.fail(f"{name} was accepted")
    # require_exp: a token without exp is refused only when asked
    assert _verify(_signed(op_key, _jwt_claims()), op_key)["sub"] == "alice"
    with pytest.raises(GrindvaktError):
        _verify(_signed(op_key, _jwt_claims()), op_key, require_exp=True)
    ok_exp = _jwt_claims(exp=int(time.time()) + 300)
    assert _verify(_signed(op_key, ok_exp), op_key, require_exp=True)["sub"] == "alice"


def test_userinfo_wrong_content_type_for_signed_body_is_not_trusted(op_key):
    """A JWT served as JSON is not accepted as claims (no sub in the body)."""
    body = jwt.sign(op_key, _jwt_claims()).encode()
    with pytest.raises(GrindvaktError):
        ui(UserinfoRecorder(body=body, ctype="application/json"))


def test_userinfo_max_age_default_and_disabled(op_key):
    old = _jwt_claims(iat=int(time.time()) - 3600)
    with pytest.raises(GrindvaktError):
        _verify(_signed(op_key, old), op_key)
    assert _verify(_signed(op_key, old), op_key, max_age=7200)["sub"] == "alice"
    undated = _jwt_claims(iat=None)
    with pytest.raises(GrindvaktError):
        _verify(_signed(op_key, undated), op_key)
    assert _verify(_signed(op_key, undated), op_key, max_age=None)["sub"] == "alice"
    assert _verify(_signed(op_key, old), op_key, max_age=None)["sub"] == "alice"


def test_userinfo_jwe_rejected():
    jwe = b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.a.b.c.d"
    with pytest.raises(AuthnError, match="encrypted") as e:
        ui(UserinfoRecorder(body=jwe, ctype="application/jwt"))
    assert e.value.code == "userinfo_encrypted"


def test_userinfo_jwks_must_be_a_jwks_dict(op_key):
    with pytest.raises(TypeError):
        ui(
            _signed(op_key, _jwt_claims()),
            jwks="not-a-jwks",
            client_id=CLIENT_ID,
            allowed_algorithms=["ES256"],
            trust="dedicated_keys",
        )


# --- RP-Initiated Logout ------------------------------------------------------


@pytest.fixture
def lprov():
    return rp.ProviderInfo(
        ISSUER,
        f"{ISSUER}/authorization",
        f"{ISSUER}/token",
        end_session_endpoint=f"{ISSUER}/logout",
    )


def test_provider_info_carries_end_session_endpoint_from_discovery(op, op_key):
    md = metadata.ProviderMetadata(ISSUER)
    md.end_session_endpoint = f"{ISSUER}/logout"
    with pytest.warns(UserWarning, match="Provider does not implement end_session_endpoint"):
        op2 = provider.Provider(
            md,
            op_key,
            client.InMemoryClientStore([]),
            tokens.TokenCodec("s"),
            token_use_store=provider.InMemoryTokenUseStore(),
        )
    discovered = rp.discover(ProviderHttpClient(op2, ISSUER), ISSUER)
    assert discovered.end_session_endpoint == f"{ISSUER}/logout"
    assert discovered.raw is not None and discovered.raw["end_session_endpoint"] == f"{ISSUER}/logout"
    info = rp.ProviderInfo.from_metadata(discovered)
    assert info.end_session_endpoint == f"{ISSUER}/logout"
    assert "end_session_endpoint" in repr(info)


def test_provider_info_without_end_session_endpoint(prov):
    assert prov.end_session_endpoint is None
    with pytest.raises(ConfigError):
        rp.end_session_url(prov)


def test_discover_raw_is_response_body(http):
    md = rp.discover(http, ISSUER)
    assert md.raw == http.op.discovery_document()


def test_provider_info_rejects_unsafe_end_session_endpoint():
    for bad in [
        "http://op.example.com/l",
        f"{ISSUER}/l#frag",
        "https://u:p@op.example.com/l",
    ]:
        with pytest.raises(GrindvaktError):
            rp.ProviderInfo(
                ISSUER,
                f"{ISSUER}/authorization",
                f"{ISSUER}/token",
                end_session_endpoint=bad,
            )


def test_from_metadata_drops_unsafe_end_session_endpoint():
    """Login must not depend on logout: a bad advertised endpoint becomes None."""
    for bad in [
        "http://evil.example/l",
        f"{ISSUER}/l#frag",
        "https://u:p@op.example.com/l",
        "not a url",
    ]:
        import json

        body = json.dumps(metadata.ProviderMetadata(ISSUER).to_dict() | {"end_session_endpoint": bad}).encode()

        class Http:
            def get(self, url, body=body):
                return 200, body, "application/json"

            def post_form(self, url, form, headers):
                raise AssertionError

        md = rp.discover(Http(), ISSUER)
        with pytest.warns(UserWarning, match="end_session_endpoint .* is unsafe"):
            info = rp.ProviderInfo.from_metadata(md)
        assert info.end_session_endpoint is None
        assert info.token_endpoint == f"{ISSUER}/token"
        with pytest.raises(ConfigError, match=r"rejected by ProviderInfo\.from_metadata") as ei:
            rp.end_session_url(info)
        assert bad not in str(ei.value)


def _pi(endpoint, issuer=ISSUER, **kw):
    return rp.ProviderInfo(
        issuer,
        f"{issuer}/authorization",
        f"{issuer}/token",
        end_session_endpoint=endpoint,
        **kw,
    )


def _md_with(endpoint, issuer=ISSUER):
    return metadata.ProviderMetadata.from_dict(
        metadata.ProviderMetadata(issuer).to_dict() | {"end_session_endpoint": endpoint}
    )


SAME_ORIGIN = [
    "https://op.example.com/l",
    "https://op.example.com:443/l",
    "https://OP.Example.COM/l",
    "HTTPS://op.example.com/l?x=1",
]
CROSS_ORIGIN = [
    "https://evil.example/logout",
    "https://sub.op.example.com/l",
    "https://op.example.com:8443/l",
    "https://op.example.com./l",
    "https://op.example.com@evil.example/l",
    "https://op.example.com.evil.example/l",
    "https://evil.example/https://op.example.com/l",
]


@pytest.mark.parametrize("ep", SAME_ORIGIN)
def test_end_session_same_origin_accepted(ep):
    assert _pi(ep).end_session_endpoint == ep
    assert rp.ProviderInfo.from_metadata(_md_with(ep)).end_session_endpoint == ep


@pytest.mark.parametrize("ep", CROSS_ORIGIN)
def test_end_session_cross_origin_rejected_and_dropped(ep):
    with pytest.raises(GrindvaktError):
        _pi(ep)
    # the userinfo-in-URL case is rejected as unsafe before the origin check
    with pytest.warns(UserWarning, match="is unsafe" if "@" in ep else "different origin than the issuer"):
        info = rp.ProviderInfo.from_metadata(_raw_md(ep))
    assert info.end_session_endpoint is None
    with pytest.raises(ConfigError, match=r"rejected by ProviderInfo\.from_metadata"):
        rp.end_session_url(info, id_token_hint="tok")


def test_from_metadata_warns_when_dropping_end_session():
    import warnings

    with pytest.warns(
        UserWarning,
        match="different origin than the issuer.*allow_cross_origin_end_session=True",
    ):
        info = rp.ProviderInfo.from_metadata(_raw_md("https://evil.example/logout"))
    assert info.end_session_endpoint is None
    with pytest.warns(UserWarning, match="unsafe"):
        rp.ProviderInfo.from_metadata(_raw_md("https://op.example.com/l#frag"))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        # a warnings filter of "error" must not make login depend on logout
        dropped = rp.ProviderInfo.from_metadata(_raw_md("https://evil.example/logout"))
        assert dropped.end_session_endpoint is None
        rp.ProviderInfo.from_metadata(_raw_md("https://op.example.com/l"))
        rp.ProviderInfo.from_metadata(_raw_md("https://evil.example/l"), allow_cross_origin_end_session=True)
        rp.ProviderInfo.from_metadata(rp.discover(_NoEndSession(), ISSUER))


class _NoEndSession:
    def get(self, url):
        return (
            200,
            json.dumps(metadata.ProviderMetadata(ISSUER).to_dict()).encode(),
            "application/json",
        )

    def post_form(self, url, form, headers):
        raise AssertionError


def test_end_session_constructor_error_says_cross_origin():
    with pytest.raises(ConfigError, match="different origin"):
        _pi("https://evil.example/logout")


def test_end_session_explicit_default_port_issuer():
    iss = "https://op.example.com:443"
    assert _pi("https://op.example.com/l", issuer=iss).end_session_endpoint == "https://op.example.com/l"


def test_end_session_loopback_http_issuer_origin_binding():
    iss = "http://localhost:8000"
    assert _pi("http://localhost:8000/l", issuer=iss).end_session_endpoint
    for bad in [
        "http://localhost:9000/l",
        "http://127.0.0.1:8000/l",
        "http://localhost/l",
    ]:
        with pytest.raises(GrindvaktError):
            _pi(bad, issuer=iss)
    # scheme differs: https on the loopback host/port is still another origin
    with pytest.raises(GrindvaktError):
        _pi("https://localhost:8000/l", issuer=iss)
    v6 = "http://[::1]:8000"
    assert _pi("http://[::1]:8000/l", issuer=v6).end_session_endpoint
    with pytest.raises(GrindvaktError):
        _pi("http://[::1]:8001/l", issuer=v6)


def test_end_session_review_poc_now_config_error():
    md = metadata.ProviderMetadata.from_dict(
        metadata.ProviderMetadata(ISSUER).to_dict() | {"end_session_endpoint": "https://evil.example/logout"}
    )
    with pytest.warns(UserWarning, match="different origin than the issuer"):
        info = rp.ProviderInfo.from_metadata(md)
    with pytest.raises(ConfigError):
        rp.end_session_url(info, id_token_hint="secret-id-token")


def test_end_session_cross_origin_opt_in():
    ep = "https://logout.other.example/l"
    info = _pi(ep, allow_cross_origin_end_session=True)
    assert info.end_session_endpoint == ep
    info2 = rp.ProviderInfo.from_metadata(_md_with(ep), allow_cross_origin_end_session=True)
    assert info2.end_session_endpoint == ep
    url = rp.end_session_url(info2, id_token_hint="tok")
    assert url.startswith("https://logout.other.example/l?") and "id_token_hint=tok" in url


def test_end_session_opt_in_still_validates_unsafe():
    for bad in [
        "http://evil.example/l",
        "https://evil.example/l#f",
        "https://u:p@evil.example/l",
    ]:
        with pytest.raises(GrindvaktError):
            _pi(bad, allow_cross_origin_end_session=True)
        with pytest.warns(UserWarning, match="end_session_endpoint .* is unsafe"):
            info = rp.ProviderInfo.from_metadata(_raw_md(bad), allow_cross_origin_end_session=True)
        assert info.end_session_endpoint is None


def _raw_md(bad):
    class Http:
        def get(self, url):
            return (
                200,
                json.dumps(metadata.ProviderMetadata(ISSUER).to_dict() | {"end_session_endpoint": bad}).encode(),
                "application/json",
            )

        def post_form(self, url, form, headers):
            raise AssertionError

    return rp.discover(Http(), ISSUER)


def _raw_md_value(value):
    """discover() output whose end_session_endpoint is ``value`` (any JSON)."""

    class Http:
        def get(self, url):
            doc = metadata.ProviderMetadata(ISSUER).to_dict() | {"end_session_endpoint": value}
            return 200, json.dumps(doc).encode(), "application/json"

        def post_form(self, url, form, headers):
            raise AssertionError

    return rp.discover(Http(), ISSUER)


_NOT_ADVERTISED = "does not advertise end_session_endpoint"
_REJECTED = "advertised value was rejected by ProviderInfo.from_metadata"
_INVALID_TYPE = "advertised a non-string end_session_endpoint"


@pytest.mark.parametrize(
    ("value", "warn_match", "wording"),
    [
        (123, r"non-string value \(number\) and was ignored", _INVALID_TYPE),
        (True, r"non-string value \(bool\) and was ignored", _INVALID_TYPE),
        ({"a": 1}, r"non-string value \(object\) and was ignored", _INVALID_TYPE),
        (["https://op.example.com/l"], r"non-string value \(array\) and was ignored", _INVALID_TYPE),
        ("", "unsafe", _REJECTED),
        ("https://evil.example/logout", "different origin", _REJECTED),
        (None, None, _NOT_ADVERTISED),
    ],
)
def test_end_session_outcome_warning_and_wording(value, warn_match, wording):
    md = _raw_md_value(value)
    if warn_match is None:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            info = rp.ProviderInfo.from_metadata(md)
    else:
        with pytest.warns(UserWarning, match=warn_match) as rec:
            info = rp.ProviderInfo.from_metadata(md)
        assert len(rec) == 1
    assert info.end_session_endpoint is None
    with pytest.raises(ConfigError, match=wording) as ei:
        rp.end_session_url(info)
    msg = str(ei.value)
    # the other two outcome wordings must not leak in
    for other in {_NOT_ADVERTISED, _REJECTED, _INVALID_TYPE} - {wording}:
        assert other not in msg
    if wording != _NOT_ADVERTISED:
        assert "UNTRUSTED" in msg and "never redirect" in msg
    assert "evil.example" not in msg and "123" not in msg


def test_end_session_absent_is_not_advertised():
    md = rp.discover(_NoEndSession_with_post(), ISSUER)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        info = rp.ProviderInfo.from_metadata(md)
    with pytest.raises(ConfigError, match=_NOT_ADVERTISED):
        rp.end_session_url(info)


class _NoEndSession_with_post(_NoEndSession):
    def post_form(self, url, form, headers):
        raise AssertionError


def test_end_session_invalid_type_warning_is_not_an_error_under_filter():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        info = rp.ProviderInfo.from_metadata(_raw_md_value(123))
    assert info.end_session_endpoint is None


def test_metadata_endpoints_are_unvalidated_but_from_metadata_rejects_unsafe_loudly():
    """info.metadata.<endpoint> is raw OP data; unsafe userinfo is refused at build time."""
    for bad in ["http://op.example.com/ui", "https://u:p@op.example.com/ui"]:
        doc = metadata.ProviderMetadata(ISSUER).to_dict() | {"userinfo_endpoint": bad}

        class Http:
            def get(self, url, doc=doc):
                return 200, json.dumps(doc).encode(), "application/json"

            def post_form(self, url, form, headers):
                raise AssertionError

        with pytest.raises(GrindvaktError):
            rp.ProviderInfo.from_metadata(rp.discover(Http(), ISSUER))
    # No way to make info.metadata.userinfo_endpoint differ from
    # info.userinfo_endpoint: from_metadata raises instead of dropping it.


def _logout_client(*uris):
    return rp.RpClient(CLIENT_ID, REDIRECT_URI, post_logout_redirect_uris=list(uris))


def test_end_session_url_params_and_encoding(lprov):
    rpc = _logout_client("https://rp.example.com/after?x=1&y=2")
    url = rp.end_session_url(
        lprov,
        id_token_hint="a.b.c",
        client=rpc,
        post_logout_redirect_uri="https://rp.example.com/after?x=1&y=2",
        state="s t&",
        logout_hint="al ice",
        ui_locales="sv en",
        extra={"foo": "b ar"},
    )
    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == f"{ISSUER}/logout"
    q = parse_qs(parts.query)
    assert q == {
        "id_token_hint": ["a.b.c"],
        "client_id": [CLIENT_ID],
        "post_logout_redirect_uri": ["https://rp.example.com/after?x=1&y=2"],
        "state": ["s t&"],
        "logout_hint": ["al ice"],
        "ui_locales": ["sv en"],
        "foo": ["b ar"],
    }
    assert "x=1&y=2" not in parts.query  # the nested URL is percent-encoded


def test_end_session_url_minimal_and_existing_query():
    p = rp.ProviderInfo(
        ISSUER,
        f"{ISSUER}/a",
        f"{ISSUER}/token",
        end_session_endpoint=f"{ISSUER}/logout?tenant=x",
    )
    assert rp.end_session_url(p) == f"{ISSUER}/logout?tenant=x"
    url = rp.end_session_url(p, id_token_hint="h")
    assert url == f"{ISSUER}/logout?tenant=x&id_token_hint=h"
    assert rp.end_session_url(p, extra=[("a", "1"), ("a", "2")]).endswith("?tenant=x&a=1&a=2")


AFTER = "https://rp.example.com/after"


def test_end_session_url_registered_post_logout_accepted(lprov):
    c = _logout_client(AFTER, "https://rp.example.com/other")
    assert c.post_logout_redirect_uris == (AFTER, "https://rp.example.com/other")
    assert "post_logout_redirect_uris" in repr(c)
    url = rp.end_session_url(lprov, client=c, post_logout_redirect_uri=AFTER)
    assert parse_qs(urlsplit(url).query)["post_logout_redirect_uri"] == [AFTER]
    rp.end_session_url(lprov, client=c, id_token_hint="h", post_logout_redirect_uri=AFTER)


def test_end_session_url_unregistered_post_logout_rejected(lprov):
    c = _logout_client(AFTER)
    with pytest.raises(BadRequestError, match="registered on the client"):
        rp.end_session_url(lprov, client=c, post_logout_redirect_uri="https://evil.example/")


@pytest.mark.parametrize(
    "near",
    [
        AFTER + "/",
        AFTER.replace("rp.", "RP."),
        "HTTPS://rp.example.com/after",
        AFTER + "?next=1",
    ],
)
def test_end_session_url_near_miss_rejected(lprov, near):
    with pytest.raises(BadRequestError, match="registered on the client"):
        rp.end_session_url(lprov, client=_logout_client(AFTER), post_logout_redirect_uri=near)


def test_end_session_url_trailing_space_rejected_as_syntax(lprov):
    # Whitespace is rejected by the binding's syntax check before the exact-match step.
    with pytest.raises(BadRequestError, match="whitespace"):
        rp.end_session_url(lprov, client=_logout_client(AFTER), post_logout_redirect_uri=AFTER + " ")


def test_end_session_url_hint_only_post_logout_rejected(lprov):
    with pytest.raises(BadRequestError, match="registered on the client"):
        rp.end_session_url(lprov, id_token_hint="h", post_logout_redirect_uri=AFTER)
    with pytest.raises(BadRequestError, match="registered on the client"):
        rp.end_session_url(lprov, post_logout_redirect_uri=AFTER)


def test_end_session_url_empty_registration_rejects_all(lprov, rpc):
    assert rpc.post_logout_redirect_uris == ()
    for c in (rpc, _logout_client()):
        with pytest.raises(BadRequestError, match="registered on the client"):
            rp.end_session_url(lprov, client=c, id_token_hint="h", post_logout_redirect_uri=AFTER)


def test_end_session_url_request_value_cannot_bypass(lprov):
    request_args = {"next": "https://evil.example/steal"}
    with pytest.raises(BadRequestError, match="registered on the client"):
        rp.end_session_url(
            lprov,
            id_token_hint="h",
            client=_logout_client(AFTER),
            post_logout_redirect_uri=request_args["next"],
        )


def test_end_session_url_post_logout_syntax_still_validated(lprov):
    with pytest.raises(ConfigError):
        _logout_client(AFTER + "#frag")
    with pytest.raises(ConfigError):
        _logout_client("relative/path")
    # Without post_logout_redirect_uri nothing changes.
    rp.end_session_url(lprov, client=_logout_client(AFTER), id_token_hint="h")


def test_end_session_url_rejects_reserved_extras_and_empty(lprov):
    for key in [
        "id_token_hint",
        "client_id",
        "post_logout_redirect_uri",
        "state",
        "logout_hint",
        "ui_locales",
    ]:
        with pytest.raises(BadRequestError, match="library-controlled"):
            rp.end_session_url(lprov, extra={key: "x"})
    with pytest.raises(BadRequestError):
        rp.end_session_url(lprov, state="")
    p = rp.ProviderInfo(
        ISSUER,
        f"{ISSUER}/a",
        f"{ISSUER}/token",
        end_session_endpoint=f"{ISSUER}/logout?state=x",
    )
    with pytest.raises(ConfigError, match="library-controlled"):
        rp.end_session_url(p)


# --- verify_id_token options ----------------------------------------------------


def _half_hash(value: str, algo: str = "sha256") -> str:
    import base64
    import hashlib

    digest = hashlib.new(algo, value.encode()).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode()


def _co(**extra):
    now = int(time.time())
    return {
        "iss": ISSUER,
        "sub": "alice",
        "aud": CLIENT_ID,
        "iat": now,
        "exp": now + 300,
        "nonce": "n",
        **extra,
    }


def _vo(op_key, claims, *args, **kw):
    token = jwt.sign(op_key, claims)
    return rp.verify_id_token(op_key.to_public_jwks(), token, ISSUER, CLIENT_ID, "n", ["ES256"], *args, **kw)


def test_verify_options_default_behaviour_unchanged(op_key):
    """at_hash / c_hash without values to check stay ignored, as before."""
    claims = _co(at_hash="x", c_hash="y", auth_time=1, acr="whatever")
    assert _vo(op_key, claims)["sub"] == "alice"


def test_verify_strict_hashes(op_key):
    at = "the-access-token"
    claims = _co(at_hash=_half_hash(at))
    with pytest.raises(AuthnError, match="at_hash"):
        _vo(op_key, claims, strict_hashes=True)
    assert _vo(op_key, claims, access_token=at, strict_hashes=True)["sub"] == "alice"
    with pytest.raises(AuthnError, match="c_hash"):
        _vo(op_key, _co(c_hash="x"), strict_hashes=True)
    # No values and no hash claims: nothing required, no ConfigError.
    assert _vo(op_key, _co(), strict_hashes=True)["sub"] == "alice"
    # Default unchanged.
    assert _vo(op_key, claims)["sub"] == "alice"
    assert _vo(op_key, _co(), access_token=at)["sub"] == "alice"


def test_verify_strict_hashes_requires_claims_when_values_given(op_key):
    at, code = "the-access-token", "the-code"
    # Value passed, claim absent: required.
    with pytest.raises(AuthnError, match="missing at_hash"):
        _vo(op_key, _co(), access_token=at, strict_hashes=True)
    with pytest.raises(AuthnError, match="missing c_hash"):
        _vo(op_key, _co(), authorization_code=code, strict_hashes=True)
    # Only one claim present while both values are passed.
    with pytest.raises(AuthnError, match="missing c_hash"):
        _vo(
            op_key,
            _co(at_hash=_half_hash(at)),
            access_token=at,
            authorization_code=code,
            strict_hashes=True,
        )
    # Both valid.
    both = _co(at_hash=_half_hash(at), c_hash=_half_hash(code))
    assert _vo(op_key, both, access_token=at, authorization_code=code, strict_hashes=True)["sub"] == "alice"
    # Wrong value still mismatches.
    with pytest.raises(AuthnError, match="at_hash mismatch"):
        _vo(
            op_key,
            both,
            access_token="other",
            authorization_code=code,
            strict_hashes=True,
        )
    # Only access_token passed: c_hash claim is unverifiable, at_hash required.
    with pytest.raises(AuthnError, match="id_token carries c_hash but no value was supplied"):
        _vo(op_key, both, access_token=at, strict_hashes=True)
    only_at = _co(at_hash=_half_hash(at))
    assert _vo(op_key, only_at, access_token=at, strict_hashes=True)["sub"] == "alice"
    # Explicit require_* combos still work.
    assert _vo(op_key, only_at, access_token=at, require_at_hash=True, strict_hashes=True)["sub"] == "alice"
    with pytest.raises(AuthnError, match="missing at_hash"):
        _vo(op_key, _co(), access_token=at, require_at_hash=True, strict_hashes=True)
    with pytest.raises(ConfigError, match="require_at_hash needs an access_token"):
        _vo(op_key, _co(), require_at_hash=True, strict_hashes=True)
    # strict_hashes off: absent claim still accepted.
    assert _vo(op_key, _co(), access_token=at, authorization_code=code)["sub"] == "alice"


def test_verify_leeway_makes_expired_token_pass(op_key):
    now = int(time.time())
    expired = _co(iat=now - 400, exp=now - 100)
    with pytest.raises(GrindvaktError):
        _vo(op_key, expired)  # default leeway is 60s
    with pytest.raises(GrindvaktError):
        _vo(op_key, expired, leeway=30)
    assert _vo(op_key, expired, leeway=200)["sub"] == "alice"


def test_verify_leeway_above_300_rejected(op_key):
    assert _vo(op_key, _co(), leeway=300)["sub"] == "alice"
    with pytest.raises(ConfigError, match="leeway"):
        _vo(op_key, _co(), leeway=301)
    with pytest.raises(ValueError, match="negative"):
        _vo(op_key, _co(), leeway=-1)


def test_verify_max_age_uses_auth_time(op_key):
    now = int(time.time())
    assert _vo(op_key, _co(auth_time=now - 10), max_age=60)["sub"] == "alice"
    with pytest.raises(AuthnError, match="older than max_age"):
        _vo(op_key, _co(auth_time=now - 120), max_age=60)
    # iat is fresh but irrelevant: auth_time decides.
    with pytest.raises(AuthnError, match="older than max_age"):
        _vo(op_key, _co(iat=now, auth_time=now - 1000), max_age=60)
    # Float auth_time is accepted; future auth_time beyond leeway is not.
    assert _vo(op_key, _co(auth_time=float(now - 5)), max_age=60)["sub"] == "alice"
    with pytest.raises(AuthnError, match="future"):
        _vo(op_key, _co(auth_time=now + 3600), max_age=60)


def test_verify_max_age_requires_auth_time(op_key):
    with pytest.raises(AuthnError, match="auth_time"):
        _vo(op_key, _co(), max_age=60)
    with pytest.raises(AuthnError, match="auth_time"):
        _vo(op_key, _co(auth_time="soon"), max_age=60)
    with pytest.raises(ValueError, match="negative"):
        _vo(op_key, _co(auth_time=1), max_age=-5)


def test_verify_acr_allow_list(op_key):
    assert _vo(op_key, _co(acr="mfa"), acr_values=["pwd", "mfa"])["acr"] == "mfa"
    with pytest.raises(AuthnError, match="acr"):
        _vo(op_key, _co(acr="pwd"), acr_values=["mfa"])
    with pytest.raises(AuthnError, match="acr"):
        _vo(op_key, _co(), acr_values=["mfa"])
    with pytest.raises(ConfigError, match="acr_values"):
        _vo(op_key, _co(acr="mfa"), acr_values=[])


def test_verify_at_hash(op_key):
    at = "the-access-token"
    claims = _co(at_hash=_half_hash(at))
    assert _vo(op_key, claims, access_token=at)["sub"] == "alice"
    with pytest.raises(AuthnError, match="at_hash mismatch"):
        _vo(op_key, claims, access_token="another-token")
    # Present but not checkable by default is still accepted (historic behaviour).
    assert _vo(op_key, claims)["sub"] == "alice"


def test_verify_require_at_hash(op_key):
    at = "the-access-token"
    with pytest.raises(AuthnError, match="missing at_hash"):
        _vo(op_key, _co(), access_token=at, require_at_hash=True)
    # Without the claim and without the requirement the token is not bound.
    assert _vo(op_key, _co(), access_token=at)["sub"] == "alice"
    assert _vo(op_key, _co(at_hash=_half_hash(at)), access_token=at, require_at_hash=True)["sub"] == "alice"


def test_verify_require_at_hash_without_access_token_is_config_error(op_key):
    with pytest.raises(ConfigError, match="require_at_hash"):
        _vo(op_key, _co(at_hash="x"), require_at_hash=True)
    with pytest.raises(ConfigError, match="require_c_hash"):
        _vo(op_key, _co(c_hash="x"), require_c_hash=True)


def test_verify_c_hash(op_key):
    code = "the-auth-code"
    claims = _co(c_hash=_half_hash(code))
    assert _vo(op_key, claims, authorization_code=code)["sub"] == "alice"
    with pytest.raises(AuthnError, match="c_hash mismatch"):
        _vo(op_key, claims, authorization_code="other-code")
    with pytest.raises(AuthnError, match="missing c_hash"):
        _vo(op_key, _co(), authorization_code=code, require_c_hash=True)
    assert _vo(op_key, claims, authorization_code=code, require_c_hash=True)["sub"] == "alice"


def test_verify_hash_with_eddsa(op_key):
    """EdDSA has no OIDC hash function: a hash claim cannot be checked."""
    ed = keys.signing_key_from_jwk(keys.generate_ed25519_jwk(), alg="EdDSA", kid="ed-1")
    jwks = ed.to_public_jwks()

    def verify(claims, **kw):
        return rp.verify_id_token(jwks, jwt.sign(ed, claims), ISSUER, CLIENT_ID, "n", ["EdDSA"], **kw)

    # No hash claim in the token: access_token alone is harmless...
    assert verify(_co(), access_token="at")["sub"] == "alice"
    # ...but requiring it is impossible to satisfy.
    with pytest.raises(AuthnError, match="missing at_hash"):
        verify(_co(), access_token="at", require_at_hash=True)
    # A hash claim present with a supplied value cannot be checked.
    with pytest.raises(CryptoError, match="token-hash"):
        verify(_co(at_hash="x"), access_token="at")
    # strict_hashes + value: claim required, which EdDSA cannot provide.
    with pytest.raises(AuthnError, match="missing at_hash"):
        verify(_co(), access_token="at", strict_hashes=True)
    with pytest.raises(CryptoError, match="token-hash"):
        verify(_co(at_hash="x"), access_token="at", strict_hashes=True)
    # strict_hashes without values: unchanged.
    assert verify(_co(), strict_hashes=True)["sub"] == "alice"


def test_verify_trusted_additional_audience_keyword(op_key):
    multi = _co(aud=[CLIENT_ID, "https://api.example"], azp=CLIENT_ID)
    with pytest.raises(AuthnError, match="untrusted audience"):
        _vo(op_key, multi)
    assert _vo(op_key, multi, trusted_additional_audiences=["https://api.example"])["sub"] == "alice"


# ---- validators and limits ----------------------------------------------------


@pytest.mark.parametrize(
    "issuer", ["https://op.example.com", "https://op.example.com/tenant", "http://localhost:8080", "http://127.0.0.1"]
)
def test_validate_issuer_accepts(issuer):
    assert rp.validate_issuer(issuer) is None


@pytest.mark.parametrize(
    "issuer",
    [
        "http://op.example.com",
        "https://op.example.com/?a=b",
        "https://op.example.com/#frag",
        "https://user@op.example.com",
        "op.example.com",
        "https://op.example.com/\u200b",
        "https://evil.example\\@op.example.com",
        "https://op.example.com\\path",
    ],
)
def test_validate_issuer_rejects(issuer):
    with pytest.raises(ConfigError):
        rp.validate_issuer(issuer)


def test_validate_redirect_uri_syntax_is_syntax_only():
    assert rp.validate_redirect_uri_syntax("https://rp.example.com/cb") is None
    assert rp.validate_redirect_uri_syntax("com.example.app:/cb") is None
    # Documented: the scheme is not checked, so this is NOT a safety check.
    assert rp.validate_redirect_uri_syntax("javascript:alert(1)") is None
    assert rp.validate_redirect_uri_syntax("http://attacker.example/cb") is None
    for bad in ("/relative", "https://rp.example.com/cb#frag", ""):
        with pytest.raises(BadRequestError):
            rp.validate_redirect_uri_syntax(bad)


BAD_REDIRECT_URIS = [
    "https://rp.example.com/cb\r\nX: 1",
    "https://rp.example.com/a\tb",
    " https://rp.example.com/cb",
    "https://rp.example.com/cb\n",
    "https://rp.example.com/\u200b",
    "https://rp.ex\u00adample.com/cb",
    "https://good.example@evil.example/cb",
    "https://u:p@rp.example.com/cb",
]


@pytest.mark.parametrize("bad", BAD_REDIRECT_URIS)
def test_validate_redirect_uri_syntax_rejects_hostile(bad):
    with pytest.raises(BadRequestError) as ei:
        rp.validate_redirect_uri_syntax(bad)
    assert "evil.example" not in str(ei.value)


@pytest.mark.parametrize("ok", ["com.example.app:/cb", "https://rp.example.com/cb?x=1", "http://127.0.0.1:8080/cb"])
def test_validate_redirect_uri_syntax_accepts(ok):
    assert rp.validate_redirect_uri_syntax(ok) is None


def test_rpclient_rejects_hostile_redirect_uris():
    bad = "https://rp.example.com/cb\r\nX: 1"
    with pytest.raises(ConfigError):
        rp.RpClient("cid", "https://rp.example.com/cb", redirect_uris=[bad])
    with pytest.raises(ConfigError):
        rp.RpClient("cid", "https://rp.example.com/cb", post_logout_redirect_uris=[bad])


def test_per_request_redirect_uri_override_rejects_hostile(prov):
    bad = "https://rp.example.com/cb\r\nX: 1"
    for allow in (False, True):
        c = rp.RpClient(CLIENT_ID, REDIRECT_URI, allow_unregistered_redirect_uri=allow)
        with pytest.raises(BadRequestError):
            rp.authorization_url(prov, c, "st", "n", redirect_uri=bad)


def test_validate_service_endpoint_with_and_without_issuer():
    assert rp.validate_service_endpoint("token_endpoint", "https://op.example.com/token") is None
    for bad in ("http://op.example.com/token", "http://localhost/token", "/token"):
        with pytest.raises(ConfigError, match="token_endpoint"):
            rp.validate_service_endpoint("token_endpoint", bad)
    # Not a same-origin check: another https host passes.
    assert rp.validate_service_endpoint("token_endpoint", "https://other.example/token", ISSUER) is None
    assert rp.validate_service_endpoint("token_endpoint", "https://op.example.com/t", issuer=ISSUER) is None


@pytest.mark.parametrize(
    "endpoint", ["http://127.0.0.1:9200/_search", "http://[::1]:6379/", "http://LocalHost:25/smtp"]
)
def test_validate_service_endpoint_loopback_http_rejected_by_default(endpoint):
    # Even with a loopback issuer, no opt-in means strict https only.
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        with pytest.raises(ConfigError):
            rp.validate_service_endpoint("token_endpoint", endpoint, "http://localhost")
        with pytest.raises(ConfigError):
            rp.validate_service_endpoint("token_endpoint", endpoint, "http://localhost", allow_loopback_http=False)
        with pytest.raises(ConfigError):
            rp.validate_service_endpoint("token_endpoint", endpoint)


@pytest.mark.parametrize(
    "endpoint", ["http://127.0.0.1:9200/_search", "http://[::1]:6379/", "http://LocalHost:25/smtp"]
)
def test_validate_service_endpoint_opt_in_loopback_warns(endpoint):
    # String validation cannot tell an attacker-supplied http://localhost from
    # a configured one, hence explicit opt-in and a loud warning.
    with pytest.warns(UserWarning, match="development-only") as rec:
        assert (
            rp.validate_service_endpoint("token_endpoint", endpoint, "http://localhost", allow_loopback_http=True)
            is None
        )
    assert "explicitly" in str(rec[0].message)


def test_validate_service_endpoint_opt_in_requires_issuer():
    with pytest.raises(ConfigError, match="requires issuer"):
        rp.validate_service_endpoint("token_endpoint", "http://localhost:8080/t", allow_loopback_http=True)
    with pytest.raises(ConfigError, match="requires issuer"):
        rp.validate_service_endpoint("token_endpoint", "https://op.example.com/t", allow_loopback_http=True)


@pytest.mark.parametrize(
    "bad_issuer", ["", "not a url", "https://op.example.com?x=1", "https://u@op.example.com", "/rel"]
)
@pytest.mark.parametrize("opt_in", [False, True])
def test_validate_service_endpoint_rejects_invalid_issuer(bad_issuer, opt_in):
    with pytest.raises(ConfigError):
        rp.validate_service_endpoint(
            "token_endpoint", "https://op.example.com/token", bad_issuer, allow_loopback_http=opt_in
        )


def test_validate_service_endpoint_https_does_not_warn():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert rp.validate_service_endpoint("token_endpoint", "https://op.example.com/t", ISSUER) is None
        assert rp.validate_service_endpoint("token_endpoint", "https://x.example/t", "http://localhost") is None
        assert rp.validate_service_endpoint("token_endpoint", "https://op.example.com/t") is None
        for issuer in (ISSUER, "http://localhost"):
            assert (
                rp.validate_service_endpoint("token_endpoint", "https://x.example/t", issuer, allow_loopback_http=True)
                is None
            )


def test_validate_service_endpoint_non_loopback_issuer_rejects_http():
    with pytest.raises(ConfigError):
        rp.validate_service_endpoint("token_endpoint", "http://127.0.0.1:9200/x", ISSUER)
    with pytest.raises(ConfigError):
        rp.validate_service_endpoint("token_endpoint", "http://127.0.0.1:9200/x", ISSUER, allow_loopback_http=True)


def test_validate_service_endpoint_allow_loopback_http_is_keyword_only():
    with pytest.raises(TypeError):
        rp.validate_service_endpoint("token_endpoint", "https://op.example.com/t", ISSUER, True)  # type: ignore[call-arg]


def test_max_id_token_leeway_matches_verify_cap(op_key):
    assert rp.MAX_ID_TOKEN_LEEWAY == 300
    assert _vo(op_key, _co(), leeway=rp.MAX_ID_TOKEN_LEEWAY)["sub"] == "alice"
    with pytest.raises(ConfigError, match="leeway"):
        _vo(op_key, _co(), leeway=rp.MAX_ID_TOKEN_LEEWAY + 1)


def test_asymmetric_algorithms(op_key):
    algs = rp.asymmetric_algorithms()
    assert isinstance(algs, list) and algs
    assert all(isinstance(a, str) for a in algs)
    assert len(set(algs)) == len(algs)
    assert not {"HS256", "HS384", "HS512", "none"} & set(algs)
    assert not any(a.startswith("HS") or a.lower() == "none" for a in algs)
    assert set(algs) == {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
        "ES256K",
    }
    for alg in algs:
        assert isinstance(jwt.supports_oidc_token_hash(alg), bool)
    # Every name passes the allowed_algorithms parser (a bad name is a ConfigError before the token is read).
    for alg in algs:
        with pytest.raises(GrindvaktError) as exc:
            rp.verify_id_token(op_key.to_public_jwks(), "not.a.jwt", ISSUER, CLIENT_ID, "n", [alg])
        assert not isinstance(exc.value, ConfigError), alg
    with pytest.raises(ConfigError):
        rp.verify_id_token(op_key.to_public_jwks(), "not.a.jwt", ISSUER, CLIENT_ID, "n", ["bogus"])


BACKSLASH_URLS = ["https://evil.example\\@op.example.com", "https://op.example.com\\path"]


@pytest.mark.parametrize("bad", BACKSLASH_URLS)
def test_backslash_urls_rejected_everywhere(bad):
    with pytest.raises(ConfigError) as ei:
        rp.validate_issuer(bad)
    assert "backslash" in str(ei.value) and "evil.example" not in str(ei.value)
    for loopback in (False, True):
        with pytest.raises(ConfigError) as ei:
            rp.validate_service_endpoint("token_endpoint", bad, "http://localhost", allow_loopback_http=loopback)
        assert "backslash" in str(ei.value) and "evil.example" not in str(ei.value)
    with pytest.raises(BadRequestError) as ei:
        rp.validate_redirect_uri_syntax(bad)
    assert "backslash" in str(ei.value) and "evil.example" not in str(ei.value)
    with pytest.raises(ConfigError):
        rp.RpClient("cid", "https://rp.example.com/cb", redirect_uris=[bad])
    with pytest.raises(ConfigError):
        rp.RpClient("cid", "https://rp.example.com/cb", post_logout_redirect_uris=[bad])
    e = OAuthError("invalid_request")
    for mode in ("query", "fragment"):
        with pytest.raises(BadRequestError) as ei:
            e.to_redirect(bad, mode)
        assert "evil.example" not in str(ei.value)


@pytest.mark.parametrize("loopback", [False, True])
def test_validate_service_endpoint_rejects_backslash_in_issuer_arg(loopback):
    with pytest.raises(ConfigError, match="backslash"):
        rp.validate_service_endpoint(
            "token_endpoint", "https://op.example.com/t", "https://op.example.com\\x", allow_loopback_http=loopback
        )


def test_backslash_gate_leaves_accepted_forms_unchanged():
    assert rp.validate_issuer("https://op.example.com/path") is None
    assert rp.validate_service_endpoint("t", "https://op.example.com/path") is None
    assert rp.validate_redirect_uri_syntax("com.example.app:/cb") is None


# --- shared-secret (HS*) algorithms and published JWKS (ADR 0006) ----------------

HS_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
HS_MIN = {"HS256": 32, "HS384": 48, "HS512": 64}


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _mac_token(secret: bytes, alg="HS256", kid="c", claims=None):
    """Sign an id_token by hand, so secrets shorter than the minimum can be used."""
    header = {"alg": alg, "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    h = _b64u(json.dumps(header).encode())
    p = _b64u(json.dumps(claims or _co()).encode())
    sig = hmac.new(secret, f"{h}.{p}".encode(), HS_HASHES[alg]).digest()
    return f"{h}.{p}.{_b64u(sig)}"


def _oct_set(secret: bytes, **extra):
    return {"keys": [{"kty": "oct", "k": _b64u(secret), "kid": "c", **extra}]}


def _verify_hs(jwks, token, alg="HS256"):
    return rp.verify_id_token(jwks, token, ISSUER, CLIENT_ID, "n", [alg])


def _json_response(value, headers=(("cache-control", "max-age=300"),)):
    return 200, json.dumps(value).encode(), "application/json", list(headers)


def _headerless_warnings(record):
    """Recorded warnings that are the one-time 'reports no response headers' one."""
    return [w for w in record if "reports no response headers" in str(w.message)]


class OctJwksHttp(ProviderHttpClient):
    """An OP that (wrongly) publishes a symmetric key next to its signing key."""

    secret = b"s" * 64

    def _answer(self, request):
        if request.method == "GET" and request.url == f"{ISSUER}/jwks":
            doc = self.op.jwks_document()
            return _json_response({"keys": [*doc["keys"], *_oct_set(self.secret)["keys"]]})
        return super()._answer(request)


@pytest.mark.parametrize(
    ("alg", "size"),
    [("HS256", 32), ("HS256", 33), ("HS256", 64), ("HS384", 48), ("HS512", 64), ("HS512", 100)],
)
@pytest.mark.parametrize("pinned", [False, True])
def test_hs_id_token_verifies_with_caller_built_oct_set(alg, size, pinned):
    """OIDC Core 10.1: the caller builds the key set from the client_secret."""
    secret = os.urandom(size)
    jwks = _oct_set(secret, **({"alg": alg} if pinned else {}))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        claims = _verify_hs(jwks, _mac_token(secret, alg), alg)
    assert claims["sub"] == "alice"
    # A key without kid is used for a token without kid too.
    del jwks["keys"][0]["kid"]
    assert _verify_hs(jwks, _mac_token(secret, alg, kid=None), alg)["sub"] == "alice"


def test_hs_poc_with_real_signing_key_roundtrip():
    secret = b"client-secret-with-at-least-32-bytes!"
    sk = keys.signing_key_from_jwk({"kty": "oct", "k": _b64u(secret)}, alg="HS256", kid="c")
    token = jwt.sign(sk, _co())
    assert _verify_hs(_oct_set(secret), token)["sub"] == "alice"


def test_hs_wrong_secret_fails_verification():
    token = _mac_token(b"a" * 40)
    with pytest.raises(GrindvaktError):
        _verify_hs(_oct_set(b"b" * 40), token)


@pytest.mark.parametrize(
    ("alg", "size"),
    [
        ("HS256", 1),
        ("HS256", 16),
        ("HS256", 24),
        ("HS256", 31),
        ("HS384", 32),
        ("HS384", 47),
        ("HS512", 48),
        ("HS512", 63),
    ],
)
@pytest.mark.parametrize("pinned", [False, True])
def test_hs_weak_shared_secret_refused(alg, size, pinned):
    """RFC 7518 3.2: a key shorter than the hash output is a ConfigError, key not echoed."""
    secret = bytes(range(1, size + 1))
    jwks = _oct_set(secret, **({"alg": alg} if pinned else {}))
    with pytest.raises(ConfigError) as exc:
        _verify_hs(jwks, _mac_token(secret, alg), alg)
    assert exc.value.code == "weak_shared_secret"
    assert isinstance(exc.value, ValueError)
    assert exc.value.status_hint == 500
    assert f"{alg} needs a shared secret of at least {HS_MIN[alg]} bytes" in str(exc.value)
    assert _b64u(secret) not in str(exc.value) and _b64u(secret) not in repr(exc.value)


def test_hs_weak_check_considers_only_the_key_named_by_kid():
    good = b"g" * 40
    jwks = {"keys": [{"kty": "oct", "k": _b64u(b"short"), "kid": "other"}, _oct_set(good)["keys"][0]]}
    assert _verify_hs(jwks, _mac_token(good))["sub"] == "alice"
    # F3: no kid on the token and several keys. verify_id_token itself refuses
    # that (OIDC Core 10.1) with an authn error, so the weak key never raises.
    with pytest.raises(AuthnError) as exc:
        _verify_hs(jwks, _mac_token(good, kid=None))
    assert getattr(exc.value, "code", None) != "weak_shared_secret"


def _ec_plus_weak_oct(op_key, **extra):
    weak = {"kty": "oct", "k": _b64u(b"short"), "kid": "legacy", **extra}
    return {"keys": [*op_key.to_public_jwks()["keys"], weak]}


def test_hs_weak_oct_not_selected_by_kid_is_not_a_config_error(op_key):
    """F3 PoC: an anonymous HS256 token naming the OP's EC key must not 500 as weak_shared_secret."""
    jwks = _ec_plus_weak_oct(op_key)
    token = _mac_token(b"x" * 40, kid="op-1")
    with pytest.raises(JoseError) as exc:
        _verify_hs(jwks, token)
    assert not isinstance(exc.value, ConfigError)
    assert exc.value.code == "jose"
    assert "does not match token header alg" in str(exc.value)
    with pytest.raises(JoseError) as exc:
        jwt.verify_with_jwks(jwks, token, jwt.Validation().with_allowed_algorithms(["HS256"]))
    assert not isinstance(exc.value, ConfigError)
    assert exc.value.code == "jose"
    # A kid that names no key fails as an authn error, not a config fault.
    with pytest.raises(AuthnError) as exc:
        _verify_hs(jwks, _mac_token(b"x" * 40, kid="nope"))
    assert exc.value.code == "authn"


def test_hs_weak_oct_selected_by_kid_is_still_a_config_error(op_key):
    """Residual: a weak oct key in a verifier set is selectable by its kid."""
    jwks = _ec_plus_weak_oct(op_key)
    token = _mac_token(b"short", kid="legacy")
    with pytest.raises(ConfigError) as exc:
        _verify_hs(jwks, token)
    assert exc.value.code == "weak_shared_secret"
    with pytest.raises(ConfigError) as exc:
        jwt.verify_with_jwks(jwks, token, jwt.Validation().with_allowed_algorithms(["HS256"]))
    assert exc.value.code == "weak_shared_secret"


def test_hs_kidless_token_single_weak_oct_key_is_a_config_error():
    weak = b"short"
    jwks = {"keys": [{"kty": "oct", "k": _b64u(weak)}]}
    with pytest.raises(ConfigError) as exc:
        _verify_hs(jwks, _mac_token(weak, kid=None))
    assert exc.value.code == "weak_shared_secret"


def test_hs_kidless_token_multi_key_set_is_not_a_config_error(op_key):
    jwks = _ec_plus_weak_oct(op_key)
    with pytest.raises(AuthnError) as exc:
        _verify_hs(jwks, _mac_token(b"short", kid=None))
    assert exc.value.code == "authn"


def test_hs_good_oct_named_by_kid_in_mixed_set_verifies(op_key):
    good = b"g" * 32
    jwks = {"keys": [*_ec_plus_weak_oct(op_key)["keys"], {"kty": "oct", "k": _b64u(good), "kid": "good"}]}
    before = copy.deepcopy(jwks)
    assert _verify_hs(jwks, _mac_token(good, kid="good"))["sub"] == "alice"
    assert jwks == before


def test_hs_only_the_allowed_algorithm_is_used():
    """An HS256 token is not verified when only ES256 is allowed (algorithm confusion)."""
    secret = b"x" * 40
    with pytest.raises(GrindvaktError):
        rp.verify_id_token(_oct_set(secret), _mac_token(secret), ISSUER, CLIENT_ID, "n", ["ES256"])
    # And the weak-key check does not fire for an algorithm that was not allowed.
    with pytest.raises(GrindvaktError) as exc:
        rp.verify_id_token(_oct_set(b"x"), _mac_token(b"x" * 40), ISSUER, CLIENT_ID, "n", ["ES256"])
    assert getattr(exc.value, "code", None) != "weak_shared_secret"


@pytest.mark.parametrize("alg", ["none", "None", "NONE"])
def test_none_algorithm_is_refused_at_parse(op_key, alg):
    token = jwt.sign(op_key, _co())
    with pytest.raises(ConfigError, match="invalid JWS algorithm") as exc:
        rp.verify_id_token(op_key.to_public_jwks(), token, ISSUER, CLIENT_ID, "n", [alg])
    assert exc.value.code == "config"
    cache = rp.JwksCache(StaticHttpClient({}), f"{ISSUER}/jwks", ISSUER)
    with pytest.raises(ConfigError, match="invalid JWS algorithm"):
        cache.verify_id_token(token, CLIENT_ID, "n", [alg])


def test_fetch_jwks_drops_oct_keys_and_warns_once(op, op_key):
    http = OctJwksHttp(op, ISSUER)
    with pytest.warns(UserWarning, match=r"symmetric \(oct\) key, ignored") as record:
        jwks = rp.fetch_jwks(http, f"{ISSUER}/jwks", ISSUER)
    assert len(record) == 1
    assert [k["kty"] for k in jwks["keys"]] == ["EC"]
    assert jwks["keys"][0]["kid"] == "op-1"
    # The published oct key can never vouch for an HS256 token.
    token = _mac_token(OctJwksHttp.secret, kid="c")
    with pytest.raises(AuthnError, match="kid"):
        _verify_hs(jwks, token)
    with pytest.raises(GrindvaktError):
        _verify_hs(jwks, _mac_token(OctJwksHttp.secret, kid=None))
    # RS/ES tokens still verify against the filtered set.
    es = jwt.sign(op_key, _co())
    assert rp.verify_id_token(jwks, es, ISSUER, CLIENT_ID, "n", ["ES256"])["sub"] == "alice"


def test_fetch_jwks_clean_set_has_no_warning(http, prov):
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        jwks = rp.fetch_jwks(http, prov.jwks_uri, prov.issuer)
    assert [k["kid"] for k in jwks["keys"]] == ["op-1"]


def test_oct_jwks_subclass_keeps_get_with_headers_and_recording(op):
    http = OctJwksHttp(op, ISSUER)
    status, body, _, _ = http.get_with_headers(f"{ISSUER}/jwks", [("X-Probe", "1")])
    assert status == 200 and b'"oct"' in body
    assert http.get(f"{ISSUER}/jwks")[0] == 200
    assert [(r.method, r.url) for r in http.calls] == [("GET", f"{ISSUER}/jwks")] * 2
    assert http.calls[0].header("x-probe") == "1"
    # Non-overridden URLs still reach the base class.
    assert http.get_with_headers(f"{ISSUER}/.well-known/openid-configuration", [])[0] == 200


def test_fetched_jwks_only_oct_gives_empty_set_that_verifies_nothing(op):
    only_oct = StaticHttpClient.from_json({f"{ISSUER}/jwks": _oct_set(OctJwksHttp.secret)})
    with pytest.warns(UserWarning, match="symmetric"):
        jwks = rp.fetch_jwks(only_oct, f"{ISSUER}/jwks", ISSUER)
    assert jwks == {"keys": []}
    with pytest.raises(GrindvaktError):
        _verify_hs(jwks, _mac_token(OctJwksHttp.secret))


def test_jwks_cache_refuses_hs_algorithms_without_fetching(op):
    http = OctJwksHttp(op, ISSUER)
    cache = rp.JwksCache(http, f"{ISSUER}/jwks", ISSUER)
    token = _mac_token(OctJwksHttp.secret)
    for algs in (["HS256"], ["ES256", "HS384"], ["HS512"]):
        with pytest.raises(ConfigError) as exc:
            cache.verify_id_token(token, CLIENT_ID, "n", algs)
        assert exc.value.code == "shared_secret_algorithm"
        assert "client_secret" in str(exc.value) and "10.1" in str(exc.value)
        # The same through rp.verify_id_token with a cache as the key set.
        with pytest.raises(ConfigError) as exc:
            rp.verify_id_token(cache, token, ISSUER, CLIENT_ID, "n", algs)
        assert exc.value.code == "shared_secret_algorithm"
    assert http.calls == []


def test_jwks_cache_fetch_drops_oct_keys_and_warns(op, op_key):
    http = OctJwksHttp(op, ISSUER)
    cache = rp.JwksCache(http, f"{ISSUER}/jwks", ISSUER)
    with pytest.warns(UserWarning, match=r"symmetric \(oct\) key, ignored") as record:
        jwks = cache.jwks()
    assert len([w for w in record if "symmetric" in str(w.message)]) == 1
    assert _headerless_warnings(record) == []
    assert [k["kty"] for k in jwks["keys"]] == ["EC"]
    with warnings.catch_warnings(record=True) as again:  # cached: no second fetch, no second warning
        warnings.simplefilter("always")
        cache.jwks()
        es = jwt.sign(op_key, _co())
        assert cache.verify_id_token(es, CLIENT_ID, "n", ["ES256"])["sub"] == "alice"
        assert rp.verify_id_token(cache, es, ISSUER, CLIENT_ID, "n", ["ES256"])["sub"] == "alice"
    assert [str(w.message) for w in again] == []


def test_userinfo_hs256_with_caller_built_set_and_cache_refusal(op):
    secret = b"u" * 40
    sk = keys.signing_key_from_jwk({"kty": "oct", "k": _b64u(secret)}, alg="HS256", kid="c")
    body = jwt.sign(sk, _jwt_claims()).encode()
    c = UserinfoRecorder(body=body, ctype="application/jwt")
    out = ui(
        c,
        jwks=_oct_set(secret),
        client_id=CLIENT_ID,
        allowed_algorithms=["HS256"],
        trust="untyped_shared_key_compat",
    )
    assert out["sub"] == "alice" and out["name"] == "A"
    # A weak secret is refused here as well.
    weak = _mac_token(b"w" * 8, claims=_jwt_claims())
    with pytest.raises(ConfigError) as exc:
        ui(
            UserinfoRecorder(body=weak.encode(), ctype="application/jwt"),
            jwks=_oct_set(b"w" * 8),
            client_id=CLIENT_ID,
            allowed_algorithms=["HS256"],
            trust="untyped_shared_key_compat",
        )
    assert exc.value.code == "weak_shared_secret"
    # A JwksCache never carries the MAC key: refused before any request.
    cache = rp.JwksCache(OctJwksHttp(op, ISSUER), f"{ISSUER}/jwks", ISSUER)
    rec = UserinfoRecorder(body=body, ctype="application/jwt")
    with pytest.raises(ConfigError) as exc:
        ui(
            rec,
            jwks=cache,
            client_id=CLIENT_ID,
            allowed_algorithms=["HS256"],
            trust="untyped_shared_key_compat",
        )
    assert exc.value.code == "shared_secret_algorithm"
    assert rec.calls == []


def test_federation_published_jwks_drops_oct_keys():
    from pygrindvakt import federation

    class Serves:
        def get(self, url):
            return 200, json.dumps(_oct_set(b"f" * 40)).encode(), "application/json"

        def post_form(self, *a):
            return 404, b"", "text/plain"

    meta = {"jwks_uri": f"{ISSUER}/jwks"}
    with pytest.warns(UserWarning, match="symmetric"):
        out = federation.entity_metadata_jwks(Serves(), meta, ISSUER, {"keys": []})
    assert out == {"keys": []}


def test_hs_incompatible_oct_keys_are_not_candidates():
    """Enc-only / other-alg oct keys are neither length-checked nor pinned."""
    good = b"g" * 40
    enc = {"kty": "oct", "k": _b64u(b"e" * 16), "alg": "A128KW"}
    enc_use = {"kty": "oct", "k": _b64u(b"e" * 16), "use": "enc"}
    enc_ops = {"kty": "oct", "k": _b64u(b"e" * 16), "key_ops": ["encrypt"]}
    unpinned_enc = {"kty": "oct", "k": _b64u(b"f" * 40), "use": "enc"}
    other_alg = {"kty": "oct", "k": _b64u(b"e" * 16), "alg": "HS384"}
    jwks = {"keys": [enc, enc_use, enc_ops, unpinned_enc, other_alg, _oct_set(good)["keys"][0]]}
    before = copy.deepcopy(jwks)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert _verify_hs(jwks, _mac_token(good))["sub"] == "alice"
    assert jwks == before
    # Without a kid jose-rs itself refuses a multi-key set; that is not a weak-secret error.
    with pytest.raises(GrindvaktError) as exc:
        _verify_hs(jwks, _mac_token(good, kid=None))
    assert getattr(exc.value, "code", None) != "weak_shared_secret"
    assert jwks == before


def test_hs_no_candidate_keys_fails_normally():
    jwks = {"keys": [{"kty": "oct", "k": _b64u(b"e" * 16), "use": "enc"}]}
    with pytest.raises(GrindvaktError) as exc:
        _verify_hs(jwks, _mac_token(b"e" * 40, kid=None))
    assert getattr(exc.value, "code", None) != "weak_shared_secret"


def test_hs_kid_scoped_selection_ignores_incompatible_key_with_other_kid():
    good = b"g" * 40
    jwks = {
        "keys": [
            {"kty": "oct", "k": _b64u(b"e" * 16), "kid": "c", "use": "enc"},
            {"kty": "oct", "k": _b64u(good), "kid": "d"},
        ]
    }
    assert _verify_hs(jwks, _mac_token(good, kid="d"))["sub"] == "alice"


def test_hs_uppercase_oct_kty_weak_key_refused_deterministically():
    secret = b"short"
    jwks = {"keys": [{"kty": "OCT", "k": _b64u(secret), "kid": "c"}]}
    with pytest.raises(ConfigError) as exc:
        _verify_hs(jwks, _mac_token(secret))
    assert exc.value.code == "weak_shared_secret"


@pytest.mark.parametrize(
    "mangle",
    [
        lambda k: k + "\n",
        lambda k: k[:5] + "=" + k[5:],
        lambda k: k + "==",
        lambda k: k[:5] + "+" + k[6:],
        lambda k: k[:5] + "/" + k[6:],
        lambda k: k[:5] + " " + k[6:],
        lambda k: k[:-1],  # n % 4 == 1
    ],
)
def test_hs_invalid_oct_key_material_refused(mangle):
    secret = b"g" * 40
    k = mangle(_b64u(secret))
    jwks = {"keys": [{"kty": "oct", "k": k, "kid": "c"}]}
    with pytest.raises(ConfigError) as exc:
        _verify_hs(jwks, _mac_token(secret))
    assert exc.value.code == "weak_shared_secret"
    assert "invalid oct key material" in str(exc.value)
    assert k not in str(exc.value) and k not in repr(exc.value)


def test_hs_31_byte_secret_with_stray_chars_not_counted_as_32():
    secret = b"g" * 31
    k = _b64u(secret) + "=="
    with pytest.raises(ConfigError) as exc:
        _verify_hs({"keys": [{"kty": "oct", "k": k, "kid": "c"}]}, _mac_token(secret))
    assert exc.value.code == "weak_shared_secret"


@pytest.mark.parametrize(("alg", "n"), [("HS256", 32), ("HS384", 48), ("HS512", 64)])
def test_hs_exact_boundary(alg, n):
    ok = b"b" * n
    assert _verify_hs(_oct_set(ok), _mac_token(ok, alg), alg)["sub"] == "alice"
    bad = b"b" * (n - 1)
    with pytest.raises(ConfigError) as exc:
        _verify_hs(_oct_set(bad), _mac_token(bad, alg), alg)
    assert exc.value.code == "weak_shared_secret"


def test_fetch_jwks_drops_uppercase_oct_kty(op, op_key):
    class UpperOct(OctJwksHttp):
        def get(self, url):
            if url == f"{ISSUER}/jwks":
                doc = self.op.jwks_document()
                oct_key = {**_oct_set(self.secret)["keys"][0], "kty": "OCT"}
                return _json_response({"keys": [*doc["keys"], oct_key]})
            return super(OctJwksHttp, self).get(url)

    with pytest.warns(UserWarning, match=r"symmetric \(oct\) key, ignored"):
        jwks = rp.fetch_jwks(UpperOct(op, ISSUER), f"{ISSUER}/jwks", ISSUER)
    assert all(k["kty"] != "OCT" for k in jwks["keys"])


# --- authorization response (callback) parsing ---------------------------------


def _parse(pairs, **kw):
    return rp.parse_authorization_response(pairs, **kw)


def test_authorization_response_round_trip_with_provider(op, prov, rpc):
    """A real OP redirect parses; state round-trips and the code is exchangeable."""
    state, verifier = "st-123", "v" * 48
    url = rp.authorization_url(prov, rpc, state, "n-1", pkce.s256_challenge(verifier))
    req = request.AuthorizationRequest.from_params(parse_qsl(urlsplit(url).query))
    op.validate_authorization_request(req)
    resp = op.authorization_redirect(req, "alice", {"email": ["a@b"]})
    pairs = parse_qsl(urlsplit(resp.header("location")).query, keep_blank_values=True)
    parsed = rp.parse_authorization_response(pairs)
    assert not parsed.is_error
    assert parsed.state == state and parsed.matches_state(state)
    assert not parsed.matches_state("st-124")
    assert parsed.code and parsed.error is None
    assert parsed.response_mode == "query"
    # This in-process Provider does not emit RFC 9207 `iss`; absent fails
    # closed unless the caller opts out (OP does not advertise the parameter).
    assert parsed.iss is None
    assert not parsed.matches_iss(ISSUER)
    assert parsed.matches_iss(ISSUER, required=False)
    with_iss = rp.parse_authorization_response([*pairs, ("iss", ISSUER)])
    assert with_iss.matches_iss(ISSUER)
    # The code is usable.
    ts = rp.exchange_code(ProviderHttpClient(op, ISSUER), prov, rpc, parsed.code, code_verifier=verifier)
    assert ts.id_token


def test_matches_state_equal_and_different():
    r = _parse([("code", "c"), ("state", "abc123")])
    assert r.matches_state("abc123") is True
    assert r.matches_state("abc124") is False
    assert r.matches_state("ABC123") is False
    assert r.matches_state("") is False


def test_matches_state_different_length():
    r = _parse([("code", "c"), ("state", "abc123")])
    assert r.matches_state("abc12") is False
    assert r.matches_state("abc1234") is False
    assert r.matches_state("abc123" * 100) is False


def test_matches_state_absent_fails_closed():
    r = _parse([("code", "c")])
    assert r.state is None
    assert r.matches_state("abc") is False
    assert r.matches_state("abc", required=True) is False
    assert r.matches_state("abc", required=False) is True


def test_matches_state_present_ignores_required():
    r = _parse([("code", "c"), ("state", "abc")])
    assert r.matches_state("abc", required=False) is True
    assert r.matches_state("xyz", required=False) is False


def test_matches_state_unicode():
    r = _parse([("code", "c"), ("state", "t\u00e4st-\u2603-\U0001f600")])
    assert r.matches_state("t\u00e4st-\u2603-\U0001f600")
    assert not r.matches_state("tast-\u2603-\U0001f600")
    # NFC vs NFD are different byte strings: no normalisation.
    assert not r.matches_state("ta\u0308st-\u2603-\U0001f600")


def test_matches_state_requires_str():
    r = _parse([("code", "c"), ("state", "abc")])
    with pytest.raises(TypeError):
        r.matches_state(b"abc")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        r.matches_state(None)  # type: ignore[arg-type]


def test_matches_state_repr_never_prints_state():
    r = _parse([("code", "c"), ("state", "sekrit-state")])
    assert "sekrit-state" not in repr(r)
    assert "state=<set>" in repr(r)


def test_authorization_response_op_error_redirect():
    e = OAuthError("access_denied", "user said no", "st-1")
    loc = e.to_redirect(REDIRECT_URI, "query").header("location")
    parsed = rp.parse_authorization_response(parse_qsl(urlsplit(loc).query))
    assert parsed.is_error and parsed.error == "access_denied" and parsed.error_known
    assert parsed.state == "st-1" and parsed.code is None
    assert parsed.error_description_safe == "user said no"


def test_authorization_response_http_request_get():
    req = pyhttp.HttpRequestData(method="GET", query=[("code", "c1"), ("state", "s1"), ("iss", ISSUER)])
    r = rp.parse_authorization_response(req)
    assert (r.code, r.state, r.iss, r.response_mode) == ("c1", "s1", ISSUER, "query")


def test_authorization_response_http_request_post_form_post():
    req = pyhttp.HttpRequestData(method="POST", form=[("code", "c1"), ("state", "s1")])
    r = rp.parse_authorization_response(req)
    assert r.response_mode == "form_post" and r.code == "c1"
    # unrelated query parameters are fine
    req = pyhttp.HttpRequestData(method="POST", query=[("utm", "x")], form=[("code", "c1")])
    assert rp.parse_authorization_response(req).code == "c1"


@pytest.mark.parametrize("name", ["code", "state", "error", "error_description", "error_uri", "iss", "response"])
def test_authorization_response_post_query_smuggle_rejected(name):
    req = pyhttp.HttpRequestData(method="POST", query=[(name, "x")], form=[("code", "c1")])
    with pytest.raises(BadRequestError):
        rp.parse_authorization_response(req, accept_jarm=True)


def test_authorization_response_http_request_mapping_query_refused():
    # PoC: a dict has already dropped any duplicate `code`.
    req = pyhttp.HttpRequestData(method="GET", query={"code": "ATTACKER", "state": "S"})
    with pytest.raises(TypeError, match=r"HttpRequestData\.query was built from a mapping"):
        rp.parse_authorization_response(req)


def test_authorization_response_http_request_mapping_form_refused():
    req = pyhttp.HttpRequestData(method="POST", form={"code": "c1", "state": "s1"})
    with pytest.raises(TypeError, match=r"HttpRequestData\.form was built from a mapping"):
        rp.parse_authorization_response(req)


def test_authorization_response_http_request_empty_mapping_not_refused():
    req = pyhttp.HttpRequestData(method="GET", query={}, form={"utm": "x"})
    with pytest.raises(BadRequestError) as exc:
        rp.parse_authorization_response(req)  # neither code nor error
    assert not isinstance(exc.value, TypeError)
    post = pyhttp.HttpRequestData(method="POST", query={}, form=[("code", "c1")])
    assert rp.parse_authorization_response(post).code == "c1"
    # a non-protocol mapping in the channel that is not read is harmless
    other = pyhttp.HttpRequestData(method="POST", query={"utm": "x"}, form=[("code", "c1")])
    assert rp.parse_authorization_response(other).code == "c1"


def test_authorization_response_http_request_pairs_duplicates_still_bad_request():
    req = pyhttp.HttpRequestData(method="GET", query=[("code", "a"), ("code", "b")])
    with pytest.raises(BadRequestError):
        rp.parse_authorization_response(req)
    post = pyhttp.HttpRequestData(method="POST", form=[("code", "a"), ("code", "b")])
    with pytest.raises(BadRequestError):
        rp.parse_authorization_response(post)


def test_authorization_response_http_request_setter_tracks_mapping():
    req = pyhttp.HttpRequestData(method="GET", query=[("code", "a"), ("code", "b")])
    with pytest.raises(BadRequestError):
        rp.parse_authorization_response(req)
    req.query = {"code": "a"}  # the old bypass: now refused, not accepted
    with pytest.raises(TypeError):
        rp.parse_authorization_response(req)
    req.query = [("code", "a"), ("state", "s")]
    assert rp.parse_authorization_response(req).code == "a"
    assert req.query_pairs == [("code", "a"), ("state", "s")]
    req.query = [("code", "a"), ("code", "b")]
    with pytest.raises(BadRequestError):
        rp.parse_authorization_response(req)
    post = pyhttp.HttpRequestData(method="POST", form=[("code", "c")])
    post.form = {"code": "c"}
    with pytest.raises(TypeError, match=r"HttpRequestData\.form"):
        rp.parse_authorization_response(post)
    post.form = [("code", "c")]
    assert rp.parse_authorization_response(post).code == "c"


def test_authorization_response_http_request_other_method_and_mode_mismatch():
    with pytest.raises(BadRequestError):
        rp.parse_authorization_response(pyhttp.HttpRequestData(method="PUT", form=[("code", "c")]))
    req = pyhttp.HttpRequestData(method="GET", query=[("code", "c")])
    with pytest.raises(ConfigError):
        rp.parse_authorization_response(req, response_mode="form_post")
    assert rp.parse_authorization_response(req, response_mode="query").response_mode == "query"


def test_authorization_response_multi_dict_input():
    r = rp.parse_authorization_response({"code": ["c1"], "state": ["s1"]}, response_mode="fragment")
    assert (r.code, r.state, r.response_mode) == ("c1", "s1", "fragment")
    parsed = rp.parse_authorization_response(dict(parse_qs("code=c1&state=s1&iss=https%3A%2F%2Fop.example.com")))
    assert parsed.iss == ISSUER
    # duplicates survive flattening and are then rejected
    with pytest.raises(BadRequestError):
        rp.parse_authorization_response({"code": ["a", "b"]})
    with pytest.raises(BadRequestError):
        rp.parse_authorization_response({"code": ["a"], "state": ["x", "y"]})


def test_authorization_response_plain_dict_is_type_error():
    with pytest.raises(TypeError, match=r"non-list value for key 'code'.*plain dict"):
        rp.parse_authorization_response({"code": "c1", "state": "s1"})
    with pytest.raises(TypeError):
        rp.parse_authorization_response("code=c1")
    with pytest.raises(TypeError):
        rp.parse_authorization_response({"code": [1]})


def test_authorization_response_response_mode_validated():
    with pytest.raises(ConfigError):
        _parse([("code", "c")], response_mode="web_message")
    for m in ("query", "fragment", "form_post"):
        assert _parse([("code", "c")], response_mode=m).response_mode == m


@pytest.mark.parametrize("name", ["code", "state", "error", "error_description", "error_uri", "iss"])
def test_authorization_response_duplicate_parameter_rejected(name):
    base = [("code", "c")] if name != "code" else []
    with pytest.raises(BadRequestError):
        _parse([*base, (name, "a"), (name, "b")])
    with pytest.raises(BadRequestError):
        _parse([*base, (name, "a"), (name, "a")])


def test_authorization_response_code_and_error_rules():
    with pytest.raises(BadRequestError):
        _parse([("code", "c"), ("error", "access_denied")])
    with pytest.raises(BadRequestError):
        _parse([("state", "s")])
    with pytest.raises(BadRequestError):
        _parse([])
    for name in ("code", "state", "error"):
        pairs = [("code", "c"), ("state", "s")] if name != "error" else [("error", "x")]
        pairs = [(k, v) for k, v in pairs if k != name] + [(name, "")]
        if name == "state":
            pairs.append(("code", "c"))
        with pytest.raises(BadRequestError):
            _parse(pairs)


def test_authorization_response_error_charset_and_length():
    for bad in ('say "hi"', "a\\b", "caf\u00e9", "a\nb", "x" * 65, "\u202e"):
        with pytest.raises(BadRequestError):
            _parse([("error", bad)])
    assert _parse([("error", "x" * 64)]).error == "x" * 64
    assert _parse([("error", "weird code!")]).error == "weird code!"


def test_authorization_response_error_known_and_unknown_kept():
    for code in (
        "access_denied",
        "invalid_request",
        "server_error",
        "login_required",
        "interaction_required",
        "invalid_dpop_proof",
    ):
        assert _parse([("error", code)]).error_known, code
    unk = _parse([("error", "totally_new_error"), ("state", "s")])
    assert unk.error == "totally_new_error" and unk.error_known is False and unk.is_error


def test_authorization_response_error_description_escaped_and_capped():
    desc = "evil\u202e\x1b[31m\ninjected\u200b\u2066"
    r = _parse([("error", "access_denied"), ("error_description", desc)])
    safe = r.error_description_safe
    assert "\u202e" not in safe and "\x1b" not in safe and "\n" not in safe
    assert "\u200b" not in safe and "\u2066" not in safe
    assert "\\u{202e}" in safe and "\\n" in safe
    long = _parse([("error", "x"), ("error_description", "a" * 5000)]).error_description_safe
    assert len(long) <= 256 and long.endswith("...")
    assert _parse([("error", "x")]).error_description_safe is None
    with pytest.raises(AttributeError):
        _parse([("error", "x"), ("error_description", "d")]).error_description  # noqa: B018


def test_authorization_response_error_uri_handling():
    ok = "https://op.example.com/docs/err?x=1"
    assert _parse([("error", "x"), ("error_uri", ok)]).error_uri == ok
    # the NORMALISED form is returned, not the raw string
    norm = {
        "https:evil.example/x": "https://evil.example/x",
        "HTTPS://OP.Example.COM:443/a/../b": "https://op.example.com/b",
        "http://127.0.0.1:8080/x": "http://127.0.0.1:8080/x",
        "http://localhost/x": "http://localhost/x",
    }
    for raw, expected in norm.items():
        assert _parse([("error", "x"), ("error_uri", raw)]).error_uri == expected, raw
    long_ok = "https://op.example.com/" + "a" * (2048 - len("https://op.example.com/"))
    assert _parse([("error", "x"), ("error_uri", long_ok)]).error_uri == long_ok
    for bad in (
        # plain http only for loopback (transport rule); no issuer-origin binding
        "http://attacker.example/x",
        "http://op.example.com",
        "http://op.example.com/e",
        "https://op.example.com/" + "a" * 2048,
        long_ok + "a",
        "http:/\\evil",
        "http:\\\\evil.example",
        "https://user:pw@op.example.com/x",
        "not a url",
        "/relative",
        "https://good.example@evil.example/x",
        "https://op.example.com/a\\b",
        "https://op.example.com/a\r\nb",
        "https://op.example.com/a b",
        "javascript:alert(1)",
        "https://op.example.com/x#frag",
        "https://op.example.com/\u202e",
        "",
    ):
        assert _parse([("error", "x"), ("error_uri", bad)]).error_uri is None, bad


# Differential baseline: outcomes identical to the pre-core-callback-wrap parser
# (verified over ~48k candidates against commit f08049e).
_ERROR_URI_BASELINE = [
    ("https://op.example.com/e", "https://op.example.com/e"),
    ("http://localhost/x", "http://localhost/x"),
    ("http://LOCALHOST/x", "http://localhost/x"),
    ("http://localhost./x", None),
    ("http://127.0.0.1:8080/x", "http://127.0.0.1:8080/x"),
    ("http://[::1]/x", "http://[::1]/x"),
    ("http://127.1/x", "http://127.0.0.1/x"),
    ("http://0x7f.1/x", "http://127.0.0.1/x"),
    ("http://[::ffff:127.0.0.1]/x", None),
    ("http://0.0.0.0/x", None),
    ("http://10.0.0.1/x", None),
    ("https://op.example.com./x", "https://op.example.com./x"),
    ("https://bücher.example/x", "https://xn--bcher-kva.example/x"),
    ("https://op.example.com/é", "https://op.example.com/%C3%A9"),
    ("https://op.example.com:99999/x", None),
    ("https://", None),
    ("https:///x", "https://x/"),
    ("https://:pw@op.example.com/x", None),
    ("http://u@localhost/x", None),
    ("https://op.example.com/x#", None),
    ("https://op.example.com/x#f", None),
    ("https://op.example.com/a\tb", None),
    ("https://op.example.com/a\x00b", None),
    ("https://op.example.com/a\x7fb", None),
    ("https://op.example.com/a\u200bb", None),
    ("https://op.example.com/a\ufeffb", None),
    ("https://op.example.com/a\u2028b", None),
    ("https://op.example.com/a\\b", None),
    ("https://op.example.com/a%5cb", "https://op.example.com/a%5cb"),
    ("https://op.example.com/%00", "https://op.example.com/%00"),
    ("\thttps://op.example.com/x", None),
    ("https://op.example.com/x\n", None),
    ("ftp://op.example.com/x", None),
    ("file:///etc/passwd", None),
    ("data:text/html,x", None),
    ("com.example.app:/cb", None),
    ("ws://op.example.com/x", None),
    ("//op.example.com/x", None),
    (" ", None),
    ("https://\u202eop.example.com", None),
    ("https://ex\u200bample.com/", None),
]


@pytest.mark.parametrize(("raw", "expected"), _ERROR_URI_BASELINE)
def test_authorization_response_error_uri_baseline(raw, expected):
    assert _parse([("error", "x"), ("error_uri", raw)]).error_uri == expected


@pytest.mark.parametrize(
    "bad",
    ["a\r\nb", "a\nb", "a\x00b", "a\\b", "a\tb", "a\x7fb", "a\u202eb", "a\u200bb", "a\u2066b", "a\ufeffb", "a\u2028b"],
)
def test_authorization_response_code_state_iss_control_chars_rejected(bad):
    with pytest.raises(BadRequestError):
        _parse([("code", bad)])
    with pytest.raises(BadRequestError):
        _parse([("code", "c"), ("state", bad)])
    with pytest.raises(BadRequestError):
        _parse([("code", "c"), ("iss", bad)])


@pytest.mark.parametrize("name", ["code", "state", "iss"])
def test_authorization_response_value_length_caps(name):
    base = [] if name == "code" else [("code", "c")]
    ok = "a" * 2048
    assert getattr(_parse([*base, (name, ok)]), name) == ok
    secret = "SECRETVALUE" + "a" * 2048
    with pytest.raises(BadRequestError) as ei:
        _parse([*base, (name, secret)])
    assert "SECRETVALUE" not in str(ei.value)


class _ListsOnly:
    """Stand-in for werkzeug's MultiDict: lists() yields (key, [values])."""

    def __init__(self, data):
        self._data = data

    def lists(self):
        return iter(self._data.items())


class _FirstValueDict(dict):
    """Stand-in for a dict subclass whose items() yields first values only."""


def test_authorization_response_lists_duck_typing():
    r = rp.parse_authorization_response(_ListsOnly({"code": ["c1"], "state": ["s1"]}))
    assert (r.code, r.state) == ("c1", "s1")
    with pytest.raises(BadRequestError):
        rp.parse_authorization_response(_ListsOnly({"code": ["a", "b"]}))
    md = _FirstValueDict({"code": "c1"})
    md.lists = lambda: iter([("code", ["a", "b"])])  # type: ignore[attr-defined]
    # a dict subclass with lists() is read through lists(), duplicates visible
    with pytest.raises(BadRequestError):
        rp.parse_authorization_response(md)


def test_authorization_response_mapping_type_error_names_key_and_hint():
    with pytest.raises(TypeError) as ei:
        rp.parse_authorization_response(_FirstValueDict({"state": ["s"], "code": "c1"}))
    msg = str(ei.value)
    assert "non-list value for key 'code'" in msg
    assert "_FirstValueDict" in msg and "items(multi=True)" in msg and ".lists()" in msg
    assert "plain dict" not in msg
    with pytest.raises(TypeError, match="non-list value for key 'code'") as ei2:
        rp.parse_authorization_response({"code": "c1"})
    assert "plain dict" in str(ei2.value)


def test_authorization_response_get_with_form_body_params_rejected():
    for name in ("code", "state", "error", "iss", "response"):
        req = pyhttp.HttpRequestData(method="GET", query=[("code", "c1")], form=[(name, "x")])
        with pytest.raises(BadRequestError):
            rp.parse_authorization_response(req, accept_jarm=True)
    ok = pyhttp.HttpRequestData(method="GET", query=[("code", "c1")], form=[("utm", "x")])
    assert rp.parse_authorization_response(ok).code == "c1"


def test_authorization_response_post_without_form_body_message():
    req = pyhttp.HttpRequestData(method="POST", query=[("utm", "x")])
    with pytest.raises(BadRequestError, match="needs a form body"):
        rp.parse_authorization_response(req)


def test_authorization_response_values_kept_verbatim():
    r = _parse([("code", " c d "), ("state", "S=/+ ")])
    assert r.code == " c d " and r.state == "S=/+ "


def test_authorization_response_matches_iss():
    r = _parse([("code", "c"), ("iss", ISSUER)])
    assert r.matches_iss(ISSUER)
    assert not r.matches_iss(ISSUER + "/")
    assert not r.matches_iss(ISSUER.upper())
    assert not r.matches_iss("https://evil.example")
    assert not r.matches_iss("")
    assert not r.matches_iss("", required=False)
    assert r.matches_iss(ISSUER, required=True) and r.matches_iss(ISSUER, required=False)
    assert not r.matches_iss("https://evil.example", required=False)
    absent = _parse([("code", "c")])
    assert absent.iss is None
    # fail closed by default (RFC 9207 section 2.4)
    assert absent.matches_iss(ISSUER) is False
    assert absent.matches_iss(ISSUER, required=True) is False
    assert absent.matches_iss(ISSUER, required=False) is True
    with pytest.raises(TypeError):
        r.matches_iss(ISSUER, True)  # type: ignore[misc]


def test_authorization_response_repr_redacts_secrets():
    r = _parse([("code", "SECRETCODE"), ("state", "SECRETSTATE"), ("iss", ISSUER)])
    text = repr(r)
    assert "SECRETCODE" not in text and "SECRETSTATE" not in text
    assert text == (
        "AuthorizationResponse(is_error=False, error=None, code=<set>, state=<set>, "
        "iss='https://op.example.com', response=None, response_mode='query')"
    )
    e = _parse([("error", "access_denied"), ("iss", ISSUER)])
    assert "state=None" in repr(e) and "error='access_denied'" in repr(e)


def test_authorization_response_repr_escapes_quote_in_quoted_fields():
    import ast

    r = _parse([("error", "it's"), ("iss", "https://op.example.com/it's")])
    text = repr(r)
    assert "error='it\\'s'" in text and "it\\'s'" in text
    assert "error='it's'" not in text
    token = text.split(", error=", 1)[1].split(", code=", 1)[0]
    assert ast.literal_eval(token) == "it's"
    iss_token = text.split("iss=", 1)[1].split(", response=", 1)[0]
    assert ast.literal_eval(iss_token) == "https://op.example.com/it's"


def test_authorization_response_repr_shows_response_set_not_value():
    jwt = "eyJhbGciOiJub25lIn0.SECRETJARM.sig"
    r = _parse([("response", jwt)], accept_jarm=True)
    assert "response=<set>" in repr(r) and "SECRETJARM" not in repr(r)
    assert r.response == jwt
    assert "response=None" in repr(_parse([("code", "c")]))


def test_authorization_response_jarm_response_cap():
    ok = "a" * 32768
    assert _parse([("response", ok)], accept_jarm=True).response == ok
    with pytest.raises(BadRequestError) as exc:
        _parse([("response", ok + "a")], accept_jarm=True)
    assert "aaaa" not in str(exc.value)


def test_authorization_response_empty_iss_rejected():
    with pytest.raises(BadRequestError) as exc:
        _parse([("code", "c"), ("iss", "")])
    assert "iss" in str(exc.value)


def test_authorization_response_empty_expected_never_matches():
    both = _parse([("code", "c"), ("state", "s"), ("iss", ISSUER)])
    absent = _parse([("code", "c")])
    for r in (both, absent):
        for required in (True, False):
            assert r.matches_iss("", required=required) is False
            assert r.matches_state("", required=required) is False


# The 12 codes OAuthError accepts (errors.rs parse_oauth_code).
_OAUTH_ERROR_CODES = [
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "unsupported_response_type",
    "invalid_scope",
    "access_denied",
    "login_required",
    "server_error",
    "temporarily_unavailable",
    "invalid_dpop_proof",
]
_RESPONSE_ONLY_CODES = [
    "interaction_required",
    "account_selection_required",
    "consent_required",
    "invalid_request_uri",
    "invalid_request_object",
    "request_not_supported",
    "request_uri_not_supported",
    "registration_not_supported",
]


@pytest.mark.parametrize("code", _OAUTH_ERROR_CODES)
def test_error_known_is_superset_of_oauth_error_codes(code):
    assert OAuthError(code).code == code
    assert _parse([("error", code)]).error_known is True


@pytest.mark.parametrize("code", _RESPONSE_ONLY_CODES)
def test_error_known_wider_than_oauth_error(code):
    assert _parse([("error", code)]).error_known is True
    with pytest.raises(ValueError):
        OAuthError(code)


def test_authorization_response_frozen_no_constructor():
    r = _parse([("code", "c")])
    with pytest.raises(AttributeError):
        r.code = "other"  # type: ignore[misc]
    with pytest.raises(TypeError):
        rp.AuthorizationResponse()  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "extra",
    [
        ("code", "c"),
        ("state", "s"),
        ("error", "access_denied"),
        ("error_description", "d"),
        ("error_uri", "https://op.example.com/e"),
        ("iss", ISSUER),
    ],
)
def test_authorization_response_jarm_rejects_plaintext_params_alongside(extra):
    with pytest.raises(BadRequestError, match="alongside"):
        _parse([("response", "a.b.c"), extra], accept_jarm=True)


def test_authorization_response_jarm_refused_by_default_accepted_raw():
    with pytest.raises(BadRequestError, match="JARM"):
        _parse([("response", "a.b.c")])
    with pytest.raises(BadRequestError):
        _parse([("code", "c"), ("response", "a.b.c")])
    r = _parse([("response", "a.b.c")], accept_jarm=True)
    assert r.response == "a.b.c" and r.code is None and not r.is_error
    # without response the usual rules still apply
    with pytest.raises(BadRequestError):
        _parse([("state", "s")], accept_jarm=True)
    with pytest.raises(BadRequestError):
        _parse([("response", "a"), ("response", "b")], accept_jarm=True)


# --- baseline locks: behaviour that must survive delegating to the core parser ---------


def test_authorization_response_parse_qsl_blank_duplicate_code_rejected():
    # keep_blank_values=True keeps the empty duplicate, so it is seen and refused
    pairs = parse_qsl("code=valid&code=&state=s", keep_blank_values=True)
    assert pairs == [("code", "valid"), ("code", ""), ("state", "s")]
    with pytest.raises(BadRequestError, match="code must not be repeated"):
        _parse(pairs)


def test_authorization_response_parse_qsl_default_hides_blank_duplicate():
    # documents the footgun: default parse_qsl drops the blank duplicate, so callers must
    # pass keep_blank_values=True to let the duplicate-code check see it
    pairs = parse_qsl("code=valid&code=&state=s")
    assert pairs == [("code", "valid"), ("state", "s")]


_LONE_SURROGATE = "\ud800"


_KNOWN_PARAMS = ("code", "state", "error", "error_description", "error_uri", "iss", "response")


def _assert_surrogate_rejected(exc_info, name):
    msg = str(exc_info.value)
    assert not isinstance(exc_info.value, (TypeError, UnicodeError))
    label = name if name in _KNOWN_PARAMS else "a request parameter"
    assert f"{label} must not contain lone surrogates" in msg
    if name not in _KNOWN_PARAMS:
        assert name not in msg
    assert "ud800" not in msg.lower() and _LONE_SURROGATE not in msg


@pytest.mark.parametrize("name", ["code", "state", "iss", "error_uri", "response", "unknown"])
def test_authorization_response_lone_surrogate_pairs_bad_request(name):
    base = [] if name in ("code", "response") else [("code", "c")]
    with pytest.raises(BadRequestError) as ei:
        _parse([*base, (name, _LONE_SURROGATE)], accept_jarm=True)
    _assert_surrogate_rejected(ei, name)


def test_authorization_response_lone_surrogate_error_description_pairs_bad_request():
    with pytest.raises(BadRequestError) as ei:
        _parse([("error", "access_denied"), ("error_description", _LONE_SURROGATE)])
    _assert_surrogate_rejected(ei, "error_description")


def test_authorization_response_lone_surrogate_jarm_response_bad_request():
    with pytest.raises(BadRequestError) as ei:
        _parse([("response", "a.b." + _LONE_SURROGATE)], accept_jarm=True)
    _assert_surrogate_rejected(ei, "response")
    with pytest.raises(BadRequestError) as ei:
        _parse([("response", "a.b." + _LONE_SURROGATE)])
    _assert_surrogate_rejected(ei, "response")


def test_authorization_response_lone_surrogate_name_bad_request():
    with pytest.raises(BadRequestError) as ei:
        _parse([("code", "c"), (_LONE_SURROGATE, "x")])
    assert "ud800" not in str(ei.value).lower() and _LONE_SURROGATE not in str(ei.value)
    with pytest.raises(BadRequestError) as ei:
        rp.parse_authorization_response({"code": ["c"], _LONE_SURROGATE: ["x"]})
    assert "ud800" not in str(ei.value).lower() and _LONE_SURROGATE not in str(ei.value)


def test_authorization_response_lone_surrogate_unknown_name_not_echoed():
    with pytest.raises(BadRequestError) as ei:
        _parse([("code", "c"), ("evil_name", _LONE_SURROGATE)])
    assert "evil_name" not in str(ei.value)
    assert "a request parameter must not contain lone surrogates" in str(ei.value)
    with pytest.raises(BadRequestError) as ei:
        rp.parse_authorization_response({"code": ["c"], "evil_name": [_LONE_SURROGATE]})
    assert "evil_name" not in str(ei.value)


def test_authorization_response_lone_surrogate_in_later_pair():
    with pytest.raises(BadRequestError) as ei:
        _parse([("code", "c"), ("state", "s"), ("iss", _LONE_SURROGATE)])
    _assert_surrogate_rejected(ei, "iss")


def test_authorization_response_lone_surrogate_in_tuple_multi_dict_value():
    with pytest.raises(BadRequestError) as ei:
        rp.parse_authorization_response({"code": ["c"], "state": ("ok", _LONE_SURROGATE)})
    _assert_surrogate_rejected(ei, "state")


@pytest.mark.parametrize("key", ["code", _LONE_SURROGATE])
def test_authorization_response_non_str_value_beats_surrogate_key(key):
    with pytest.raises(TypeError, match="params must be"):
        _parse([(key, 1)])
    with pytest.raises(TypeError, match="parameter values must be str"):
        rp.parse_authorization_response({key: [1]})


def test_authorization_response_non_str_value_before_surrogate_value_in_list():
    with pytest.raises(TypeError, match="parameter values must be str"):
        rp.parse_authorization_response({"code": [_LONE_SURROGATE, 1]})


@pytest.mark.parametrize(
    "make",
    [
        lambda pairs: set(pairs),
        lambda pairs: (p for p in pairs),
        lambda pairs: iter(pairs),
        lambda pairs: frozenset(pairs),
    ],
    ids=["set", "generator", "iterator", "frozenset"],
)
def test_authorization_response_pairs_must_be_sequence(make):
    with pytest.raises(TypeError, match="params must be"):
        _parse(make([("code", "a"), ("code", "a")]))


def test_authorization_response_dict_views_type_error():
    d = {"code": "a"}
    for view in (d.items(), d.keys(), d.values()):
        with pytest.raises(TypeError, match="params must be"):
            _parse(view)


@pytest.mark.parametrize("wrapper", ["multi-dict", "lists-only"])
@pytest.mark.parametrize("key", ["code", "state", "iss", "response"])
def test_authorization_response_lone_surrogate_duck_bad_request(wrapper, key):
    base = {} if key in ("code", "response") else {"code": ["c"]}
    data = {**base, key: [_LONE_SURROGATE]}
    params = data if wrapper == "multi-dict" else _ListsOnly(data)
    with pytest.raises(BadRequestError) as ei:
        rp.parse_authorization_response(params, accept_jarm=True)
    _assert_surrogate_rejected(ei, key)


@pytest.mark.parametrize("bad", [b"c", 1, None])
def test_authorization_response_non_str_value_stays_type_error(bad):
    with pytest.raises(TypeError, match="params must be"):
        _parse([("code", bad)])
    with pytest.raises(TypeError, match="parameter values must be str"):
        rp.parse_authorization_response({"code": [bad]})


def test_authorization_response_lone_surrogate_http_request_data_type_error():
    # the TypeError comes from the HttpRequestData constructor, before any parsing
    with pytest.raises(TypeError, match="query must be a dict"):
        pyhttp.HttpRequestData(method="GET", query=[("code", _LONE_SURROGATE)])
    with pytest.raises(TypeError, match="form must be a dict"):
        pyhttp.HttpRequestData(method="POST", form=[("code", _LONE_SURROGATE)])


def test_authorization_response_error_description_safe_exact_escapes():
    r = _parse([("error", "x"), ("error_description", "a\x1bb\n")])
    assert r.error_description_safe == "a\\u{001b}b\\n"
    r = _parse([("error", "x"), ("error_description", "a\tb\rc\\d\u202e")])
    assert r.error_description_safe == "a\\tb\\rc\\\\d\\u{202e}"


def test_authorization_response_error_description_safe_cap_exact_length():
    safe = _parse([("error", "x"), ("error_description", "a" * 300)]).error_description_safe
    assert len(safe) == 256 and safe == "a" * 253 + "..."
    exact = _parse([("error", "x"), ("error_description", "a" * 256)]).error_description_safe
    assert exact == "a" * 256


@pytest.mark.parametrize("name", ["code", "state", "iss"])
def test_authorization_response_value_length_boundary_exact(name):
    base = [] if name == "code" else [("code", "c")]
    assert getattr(_parse([*base, (name, "a" * 2048)]), name) == "a" * 2048
    with pytest.raises(BadRequestError, match=f"{name} must be at most 2048 characters"):
        _parse([*base, (name, "a" * 2049)])


def test_authorization_response_error_and_jarm_boundary_exact():
    assert _parse([("error", "x" * 64)]).error == "x" * 64
    with pytest.raises(BadRequestError, match="error must be at most 64 characters"):
        _parse([("error", "x" * 65)])
    assert _parse([("response", "a" * 32768)], accept_jarm=True).response == "a" * 32768
    with pytest.raises(BadRequestError, match="response must be at most 32768 characters"):
        _parse([("response", "a" * 32769)], accept_jarm=True)


def test_authorization_response_jarm_refusal_message():
    with pytest.raises(BadRequestError) as ei:
        _parse([("response", "a.b.c")])
    assert str(ei.value) == (
        "bad request: JARM response parameter is not supported; pass accept_jarm=True only if you "
        "verify the JWT yourself"
    )


def test_authorization_response_mode_mismatch_messages():
    get = pyhttp.HttpRequestData(method="GET", query=[("code", "c")])
    with pytest.raises(ConfigError) as ei:
        rp.parse_authorization_response(get, response_mode="form_post")
    assert str(ei.value) == (
        'response_mode "form_post" does not match the request (GET is "query"); '
        "omit response_mode for an HttpRequestData"
    )
    post = pyhttp.HttpRequestData(method="POST", form=[("code", "c")])
    with pytest.raises(ConfigError) as ei:
        rp.parse_authorization_response(post, response_mode="query")
    assert str(ei.value) == (
        'response_mode "query" does not match the request (POST is "form_post"); '
        "omit response_mode for an HttpRequestData"
    )


def test_authorization_response_empty_post_needs_form_body_message():
    with pytest.raises(BadRequestError) as ei:
        rp.parse_authorization_response(pyhttp.HttpRequestData(method="POST"))
    assert str(ei.value) == (
        "bad request: a form_post callback needs a form body: parse the form before building the "
        "HttpRequestData (no form parameters were found)"
    )


def test_authorization_response_empty_jarm_response_rejected():
    with pytest.raises(BadRequestError) as ei:
        _parse([("response", "")], accept_jarm=True)
    assert str(ei.value) == "bad request: response must not be empty"


def test_authorization_response_empty_jarm_without_accept_jarm_refused_first():
    with pytest.raises(BadRequestError) as ei:
        _parse([("response", "")])
    assert str(ei.value) == (
        "bad request: JARM response parameter is not supported; pass accept_jarm=True only if "
        "you verify the JWT yourself"
    )


def test_authorization_response_empty_jarm_alongside_code_reported_before_empty():
    with pytest.raises(BadRequestError) as ei:
        _parse([("response", ""), ("code", "c")], accept_jarm=True)
    assert str(ei.value) == (
        "bad request: a JARM response carries every parameter inside the JWT: code, state, "
        "error, error_description, error_uri and iss must not appear alongside response"
    )


def test_authorization_response_jarm_stub_matches_always_false():
    r = _parse([("response", "a.b.c")], accept_jarm=True)
    assert r.matches_state("x", required=False) is False
    assert r.matches_iss("x", required=False) is False
    assert r.matches_state("x") is False and r.matches_iss("x") is False


# --- G6 helpers: BeginResult, TokenSet getters, claims_audiences, metadata ----------------


def test_begin_result_is_a_real_namedtuple(prov, rpc):
    res = rp.begin(prov, rpc)
    assert isinstance(res, rp.BeginResult)
    assert isinstance(res, tuple)
    assert res._fields == ("url", "state", "nonce", "code_verifier")
    url, state, nonce, verifier = res
    assert (res.url, res.state, res.nonce, res.code_verifier) == (url, state, nonce, verifier)
    assert res[0] == url and res[3] == verifier and len(res) == 4
    assert res == (url, state, nonce, verifier)
    assert rp.BeginResult.__module__ == "pygrindvakt.rp"
    assert rp.BeginResult is type(res)
    assert res._replace(state="x").state == "x"


def test_begin_result_pickles(prov, rpc):
    import pickle

    res = rp.begin(prov, rpc)
    assert pickle.loads(pickle.dumps(res)) == res


def test_begin_result_repr_redacts(prov, rpc):
    res = rp.begin(prov, rpc)
    text = repr(res)
    assert text.startswith("BeginResult(url='https://op.example.com/authorization?")
    assert "state=<redacted>, nonce=<redacted>, code_verifier=<redacted>)" in text
    for secret in (res.state, res.nonce, res.code_verifier, res.url):
        assert secret not in text
    assert "code_challenge" not in text
    assert str(res) == text
    no_pkce = repr(rp.begin(prov, rpc, pkce=False))
    assert "code_verifier=None" in no_pkce


class _TokenHttp:
    """Serves a canned token-endpoint body."""

    def __init__(self, body):
        self.body = body

    def get(self, url):
        return 404, b"", "text/plain"

    def post_form(self, url, form, headers):
        return 200, json.dumps(self.body).encode(), "application/json"


def _token_set(prov, rpc, **extra):
    body = {"access_token": "AT-secret", "id_token": "a.b.c", "token_type": "Bearer", **extra}
    return rp.exchange_code(_TokenHttp(body), prov, rpc, "code", "v" * 43)


def test_token_set_new_getters(prov, rpc):
    ts = _token_set(prov, rpc, refresh_token="RT-secret", expires_in=3600, scope="openid email")
    assert ts.refresh_token == "RT-secret"
    assert ts.expires_in == 3600
    assert ts.scope == "openid email"
    assert ts.raw["refresh_token"] == "RT-secret"
    assert "RT-secret" not in repr(ts) and "AT-secret" not in repr(ts)
    assert "refresh_token=<set>" in repr(ts)


def test_token_set_getters_missing(prov, rpc):
    ts = _token_set(prov, rpc)
    assert ts.refresh_token is None and ts.expires_in is None and ts.scope is None
    assert "refresh_token=None" in repr(ts)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (3600, 3600),
        (0, 0),
        ("3600", 3600),
        (3600.0, 3600),
        (-1, None),
        ("-1", None),
        (1.5, None),
        ("1.5", None),
        ("", None),
        (" 60", None),
        ("abc", None),
        ("١٢", None),
        (None, None),
        (True, None),
        ([60], None),
        ({"a": 1}, None),
        (10**30, None),
        (315_360_000, 315_360_000),
        (315_360_001, None),
        (2**64 - 1, None),
        (2**64, None),
        ("315360000", 315_360_000),
        ("315360001", None),
        (str(2**64 - 1), None),
        (315_360_000.0, 315_360_000),
        (315_360_001.0, None),
    ],
)
def test_token_set_expires_in(prov, rpc, value, expected):
    assert _token_set(prov, rpc, expires_in=value).expires_in == expected


def test_token_set_wrong_types_are_none(prov, rpc):
    ts = _token_set(prov, rpc, refresh_token=5, scope=["a"])
    assert ts.refresh_token is None and ts.scope is None


def test_claims_audiences():
    assert rp.claims_audiences({"aud": "a"}) == ["a"]
    assert rp.claims_audiences({"aud": ["a", "b"]}) == ["a", "b"]
    assert rp.claims_audiences({"aud": "x"}) == ["x"]
    assert rp.claims_audiences({"aud": ["x", "y"]}) == ["x", "y"]
    assert rp.claims_audiences({"aud": ("x", "y")}) == ["x", "y"]


@pytest.mark.parametrize(
    "claims, msg",
    [
        ({}, "no 'aud'"),
        ({"sub": "x"}, "no 'aud'"),
        ({"aud": []}, "empty 'aud'"),
        ({"aud": ()}, "empty 'aud'"),
        ({"aud": ""}, "empty 'aud'"),
        ({"aud": ["a", ""]}, "empty 'aud'"),
        ({"aud": [""]}, "empty 'aud'"),
    ],
)
def test_claims_audiences_fails_closed(claims, msg):
    with pytest.raises(BadRequestError, match=msg):
        rp.claims_audiences(claims)


def test_claims_audiences_no_vacuous_audience_check(rp_key):
    """A verified token without aud must not reach a hand-rolled all(...) check."""
    jws = jwt.sign(rp_key, {"sub": "s", "iss": ISSUER, "exp": int(time.time()) + 300})
    v = jwt.Validation().with_issuer(ISSUER).require_exp()
    claims = jwt.verify_with_jwks(rp_key.to_public_jwks(), jws, v)
    assert "aud" not in claims
    with pytest.raises(BadRequestError, match="no 'aud'"):
        rp.claims_audiences(claims)
    # control: an aud is returned and checked normally
    jws = jwt.sign(rp_key, {"sub": "s", "iss": ISSUER, "aud": "other-rp", "exp": int(time.time()) + 300})
    claims = jwt.verify_with_jwks(rp_key.to_public_jwks(), jws, v)
    auds = rp.claims_audiences(claims)
    assert auds == ["other-rp"]
    assert not all(a in {CLIENT_ID} for a in auds)


@pytest.mark.parametrize("aud", ["\ud800", ["ok", "\udc00"], ("\ud800",)])
def test_claims_audiences_lone_surrogate_is_bad_request(aud):
    with pytest.raises(BadRequestError) as ei:
        rp.claims_audiences({"aud": aud})
    assert not isinstance(ei.value, UnicodeError)
    assert "ud800" not in str(ei.value) and "udc00" not in str(ei.value)


def test_claims_audiences_does_not_mutate():
    claims = {"aud": ["a", "b"], "sub": "s"}
    snapshot = copy.deepcopy(claims)
    out = rp.claims_audiences(claims)
    out.append("z")
    assert claims == snapshot
    single = {"aud": "a"}
    rp.claims_audiences(single)
    assert single == {"aud": "a"}


@pytest.mark.parametrize("aud", [None, 5, ["a", 1], ["a", None], {"a": 1}, b"a", [["a"]]])
def test_claims_audiences_bad_types(aud):
    with pytest.raises(BadRequestError):
        rp.claims_audiences({"aud": aud})


def test_claims_audiences_not_a_mapping():
    with pytest.raises(TypeError):
        rp.claims_audiences(["aud"])  # type: ignore[arg-type]


def test_provider_info_metadata(prov, op):
    assert prov.metadata is not None
    assert prov.metadata.issuer == ISSUER
    assert prov.metadata.code_challenge_methods_supported == ["S256"]
    assert "metadata" not in repr(prov)
    hand = rp.ProviderInfo(ISSUER, f"{ISSUER}/authorization", f"{ISSUER}/token")
    assert hand.metadata is None


def test_provider_info_metadata_is_a_copy(prov):
    first = prov.metadata
    first.scopes_supported = ["changed"]
    assert prov.metadata.scopes_supported != ["changed"]


def test_provider_info_metadata_keeps_rejected_end_session():
    with pytest.warns(UserWarning, match="different origin than the issuer"):
        info = rp.ProviderInfo.from_metadata(_raw_md("https://evil.example/logout"))
    assert info.end_session_endpoint is None
    assert info.metadata.end_session_endpoint == "https://evil.example/logout"
    # "not advertised" differs from "rejected"
    clean = rp.ProviderInfo.from_metadata(rp.discover(_NoEndSession(), ISSUER))
    assert clean.end_session_endpoint is None and clean.metadata.end_session_endpoint is None


def test_end_session_url_error_distinguishes_rejected_from_not_advertised():
    raw = "https://evil.example/logout"
    with pytest.warns(UserWarning):
        rejected = rp.ProviderInfo.from_metadata(_raw_md(raw))
    with pytest.raises(ConfigError, match=r"rejected by ProviderInfo\.from_metadata") as ei:
        rp.end_session_url(rejected)
    assert raw not in str(ei.value) and "does not advertise" not in str(ei.value)
    clean = rp.ProviderInfo.from_metadata(rp.discover(_NoEndSession(), ISSUER))
    with pytest.raises(ConfigError, match="does not advertise end_session_endpoint") as ei:
        rp.end_session_url(clean)
    assert "rejected" not in str(ei.value)
    hand = rp.ProviderInfo(ISSUER, f"{ISSUER}/authorization", f"{ISSUER}/token")
    with pytest.raises(ConfigError, match="does not advertise"):
        rp.end_session_url(hand)


# --- check_rp_compatibility -----------------------------------------------------------------


def _md(**changes):
    md = metadata.ProviderMetadata(ISSUER)
    for k, v in changes.items():
        setattr(md, k, v)
    return md


def test_compat_against_in_process_op(prov, rpc):
    assert rp.check_rp_compatibility(prov) == []
    assert (
        rp.check_rp_compatibility(
            prov,
            client=rpc,
            pkce=True,
            algorithms=rp.asymmetric_algorithms(),
            scopes=["openid", "email"],
        )
        == []
    )
    assert rp.check_rp_compatibility(prov.metadata, pkce=True) == []


def test_compat_ok_with_pkce_unset_or_false():
    md = _md(code_challenge_methods_supported=["plain"])
    assert rp.check_rp_compatibility(md) == []
    assert rp.check_rp_compatibility(md, pkce=False) == []


def test_compat_response_type_mismatch():
    out = rp.check_rp_compatibility(_md(response_types_supported=["id_token"]))
    assert len(out) == 1 and "'code'" in out[0] and not out[0].startswith("not advertised:")
    out = rp.check_rp_compatibility(_md(response_types_supported=[]))
    assert len(out) == 1 and out[0].startswith("not advertised: response_types_supported")


def test_compat_pkce_mismatch_and_not_advertised():
    out = rp.check_rp_compatibility(_md(code_challenge_methods_supported=["plain"]), pkce=True)
    assert len(out) == 1 and "S256" in out[0] and not out[0].startswith("not advertised:")
    # ORCID-like: nothing advertised
    out = rp.check_rp_compatibility(_md(code_challenge_methods_supported=[]), pkce=True)
    assert out == ["not advertised: code_challenge_methods_supported (cannot confirm PKCE S256 support)"]


def test_compat_algorithms():
    md = _md(id_token_signing_alg_values_supported=["RS256"])
    assert rp.check_rp_compatibility(md, algorithms=["RS256", "ES256"]) == []
    out = rp.check_rp_compatibility(md, algorithms=["ES256", "EdDSA"])
    assert len(out) == 1 and "id_token_signing_alg_values_supported" in out[0]
    assert not out[0].startswith("not advertised:")
    out = rp.check_rp_compatibility(_md(id_token_signing_alg_values_supported=[]), algorithms=["ES256"])
    assert len(out) == 1 and out[0].startswith("not advertised: id_token_signing_alg_values_supported")
    with pytest.raises(ConfigError):
        rp.check_rp_compatibility(md, algorithms=[])


def _hs_none_md(algs=("HS256", "none", "RS256")):
    return metadata.ProviderMetadata.from_dict(
        {**metadata.ProviderMetadata(ISSUER).to_dict(), "id_token_signing_alg_values_supported": list(algs)}
    )


def test_compat_hs_refused_by_default():
    md = _hs_none_md()
    out = rp.check_rp_compatibility(md, algorithms=["HS256"])
    assert out != []
    assert len(out) == 1 and not out[0].startswith("not advertised:")
    assert "shared_secret_keys=True" in out[0] and "ADR 0006" in out[0]
    # HS alone against an OP advertising it: only the HS message, no intersection noise
    out = rp.check_rp_compatibility(_hs_none_md(["HS256"]), algorithms=["HS256"])
    assert len(out) == 1 and "client_secret" in out[0]
    # mixed: HS message only, RS256 intersects
    out = rp.check_rp_compatibility(_hs_none_md(["HS256", "RS256"]), algorithms=["HS256", "RS256"])
    assert len(out) == 1 and "client_secret" in out[0]
    assert rp.check_rp_compatibility(md, algorithms=["RS256"]) == []
    assert rp.check_rp_compatibility(md, algorithms=["RS256"], shared_secret_keys=True) == []
    out = rp.check_rp_compatibility(md, algorithms=["hs384"])
    assert len(out) == 1 and "client_secret" in out[0]


def test_compat_none_always_refused():
    md = _hs_none_md()
    for shared in (False, True):
        out = rp.check_rp_compatibility(md, algorithms=["none"], shared_secret_keys=shared)
        assert len(out) == 1 and "'none'" in out[0] and "ADR 0006" in out[0]
        assert not out[0].startswith("not advertised:")
        assert "fix the RP config, not the OP" in out[0]
        out = rp.check_rp_compatibility(md, algorithms=["NONE"], shared_secret_keys=shared)
        assert len(out) == 1 and "'NONE'" in out[0]
        # none never counts as an intersection match
        out = rp.check_rp_compatibility(md, algorithms=["none", "ES256"], shared_secret_keys=shared)
        assert len(out) == 2 and "always refused" in out[0] and "none of the allowed" in out[1]
    out = rp.check_rp_compatibility(md, algorithms=["HS512", "none"])
    assert len(out) == 2
    assert any("always refused" in m for m in out) and any("client_secret" in m for m in out)


def test_compat_shared_secret_keys():
    md = _hs_none_md()
    assert rp.check_rp_compatibility(md, algorithms=["HS256"], shared_secret_keys=True) == []
    out = rp.check_rp_compatibility(_hs_none_md(["RS256"]), algorithms=["HS256"], shared_secret_keys=True)
    assert len(out) == 1 and out[0].startswith("none of the allowed id_token algorithms")
    out = rp.check_rp_compatibility(_hs_none_md([]), algorithms=["HS256"], shared_secret_keys=True)
    assert len(out) == 1 and out[0].startswith("not advertised:")
    out = rp.check_rp_compatibility(md, algorithms=["HS512", "none"], shared_secret_keys=True)
    assert len(out) == 2 and "always refused" in out[0] and "none of the allowed" in out[1]


def test_compat_alg_messages_escaped():
    evil = "ES\u202e256\n" + "x" * 100
    md = _hs_none_md(["RS256"])
    out = rp.check_rp_compatibility(md, algorithms=[evil, "HS256", "none"])
    joined = "\n".join(out)
    assert "\u202e" not in joined and "x" * 65 not in joined
    assert "\\u{202e}" in joined
    many = [f"HS{i}" for i in range(30)] + ["HS256"]
    out = rp.check_rp_compatibility(md, algorithms=many)
    assert any("more)" in m for m in out)


def test_compat_scopes():
    md = _md(scopes_supported=["openid", "email"])
    assert rp.check_rp_compatibility(md, scopes=["openid"]) == []
    out = rp.check_rp_compatibility(md, scopes=["openid", "groups", "phone"])
    assert len(out) == 1 and "'groups'" in out[0] and "'phone'" in out[0] and "'openid', " not in out[0].split("(")[0]
    out = rp.check_rp_compatibility(_md(scopes_supported=[]), scopes=["openid"])
    assert len(out) == 1 and out[0].startswith("not advertised: scopes_supported")


def test_compat_acr_values():
    assert rp.check_rp_compatibility(_md(), acr_values=["urn:x"])[0].startswith("not advertised: acr_values_supported")
    md = _md(acr_values_supported=["urn:a", "urn:b"])
    assert rp.check_rp_compatibility(md, acr_values=["urn:a"]) == []
    out = rp.check_rp_compatibility(md, acr_values=["urn:a", "urn:c"])
    assert len(out) == 1 and "'urn:c'" in out[0] and not out[0].startswith("not advertised:")
    # not requested: no message even though nothing is advertised
    assert rp.check_rp_compatibility(_md()) == []


def test_compat_client_auth_method():
    pk = rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret="s")
    md = _md(token_endpoint_auth_methods_supported=["private_key_jwt"])
    out = rp.check_rp_compatibility(md, client=pk)
    assert len(out) == 1 and "client_secret_basic" in out[0] and not out[0].startswith("not advertised:")
    ok = _md(token_endpoint_auth_methods_supported=["client_secret_basic"])
    assert rp.check_rp_compatibility(ok, client=pk) == []


def test_compat_client_auth_method_absent_assumes_spec_default():
    # OIDC Discovery 1.0 s3 / RFC 8414 s2: absent means ["client_secret_basic"].
    basic = rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret="s")
    post = rp.RpClient(CLIENT_ID, REDIRECT_URI, client_secret="s", auth_method="client_secret_post")
    pub = rp.RpClient(CLIENT_ID, REDIRECT_URI)

    class _NoAuthMethods:
        def get(self, url):
            doc = metadata.ProviderMetadata(ISSUER).to_dict()
            doc.pop("token_endpoint_auth_methods_supported", None)
            return 200, json.dumps(doc).encode(), "application/json"

        def post_form(self, url, form, headers):
            raise AssertionError

    absent = rp.discover(_NoAuthMethods(), ISSUER)
    for md in (absent, _md(token_endpoint_auth_methods_supported=[])):
        assert rp.check_rp_compatibility(md, client=basic) == []
        for c, name in ((post, "client_secret_post"), (pub, "none")):
            out = rp.check_rp_compatibility(md, client=c)
            assert len(out) == 1 and not out[0].startswith("not advertised:")
            assert name in out[0] and "absent" in out[0] and "client_secret_basic" in out[0]


def test_compat_reports_several_and_escapes_untrusted():
    md = _md(response_types_supported=["code\u202e\nevil"], code_challenge_methods_supported=["plain"])
    out = rp.check_rp_compatibility(md, pkce=True)
    assert len(out) == 2
    assert all("\n" not in m and "\u202e" not in m for m in out)


def test_compat_provider_info_without_metadata():
    hand = rp.ProviderInfo(ISSUER, f"{ISSUER}/authorization", f"{ISSUER}/token")
    with pytest.raises(ConfigError, match="no metadata"):
        rp.check_rp_compatibility(hand)
    with pytest.raises(TypeError):
        rp.check_rp_compatibility({"issuer": ISSUER})  # type: ignore[arg-type]
