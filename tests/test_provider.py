"""OpenID Provider flows driven the way a web app would drive them."""

import base64
import contextlib
import hashlib
import json
import time
from urllib.parse import parse_qs, urlparse

import pytest
from conftest import ISSUER, REDIRECT_URI, TOKEN_URL, basic_auth, code_from_redirect
from pygrindvakt import (
    ConfigError,
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


def authz(op, verifier=None, **extra):
    """Run the front half of a code flow; return (request, code)."""
    params = {
        "client_id": "demo",
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "openid email",
        "state": "st",
        "nonce": "n1",
    }
    if verifier:
        params["code_challenge"] = pkce.s256_challenge(verifier)
        params["code_challenge_method"] = "S256"
    params.update(extra)
    req = request.AuthorizationRequest.from_params(list(params.items()))
    op.validate_authorization_request(req)
    resp = op.authorization_redirect(req, "alice", {"email": ["alice@example.com"], "email_verified": ["true"]})
    return req, code_from_redirect(resp)


def test_discovery_and_jwks(op):
    """Discovery reflects the configured issuer; JWKS carries the signing key only."""
    d = op.discovery_document()
    assert d["issuer"] == ISSUER and d["token_endpoint"] == TOKEN_URL
    assert d["code_challenge_methods_supported"] == ["S256"]
    j = op.jwks_document()
    assert [k["kid"] for k in j["keys"]] == ["op-1"] and "d" not in j["keys"][0]
    assert op.issuer == ISSUER and op.metadata.issuer == ISSUER
    assert op.signing_key.kid == "op-1"
    assert op.lifetimes.code_ttl == 600


def test_full_code_flow_with_pkce(op):
    """authorization_code + PKCE + client_secret_basic, then userinfo and refresh."""
    verifier = util.random_token(32)
    _req, code = authz(op, verifier)
    tr = op.handle_token_request(
        list(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": verifier,
            }.items()
        ),
        TOKEN_URL,
        auth_header=basic_auth("demo", "s3cret"),
    )
    assert tr.token_type == "Bearer" and tr.expires_in == 3600 and tr.refresh_token
    body = tr.to_dict()
    assert set(body) >= {
        "access_token",
        "id_token",
        "token_type",
        "expires_in",
        "refresh_token",
    }
    r = tr.to_response()
    assert r.status == 200 and r.header("cache-control") == "no-store" and json.loads(r.body)["token_type"] == "Bearer"
    claims = rp.verify_id_token(op.jwks_document(), tr.id_token, ISSUER, "demo", "n1", ["ES256"])
    assert claims["sub"] == "alice" and claims["email"] == "alice@example.com" and claims["email_verified"] is True
    ui = op.userinfo(tr.access_token)
    assert ui == {"sub": "alice", "email": "alice@example.com", "email_verified": True}
    tr2 = op.handle_token_request(
        list({"grant_type": "refresh_token", "refresh_token": tr.refresh_token}.items()),
        TOKEN_URL,
        auth_header=basic_auth("demo", "s3cret"),
    )
    assert tr2.refresh_token != tr.refresh_token
    with pytest.raises(OAuthError) as ei:  # old refresh token is single-use
        op.handle_token_request(
            list(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": tr.refresh_token,
                }.items()
            ),
            TOKEN_URL,
            auth_header=basic_auth("demo", "s3cret"),
        )
    assert ei.value.code == "invalid_grant"


def test_code_replay_rejected(op):
    """Consuming the same authorization code twice fails with invalid_grant."""
    verifier = util.random_token(32)
    _, code = authz(op, verifier)
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier,
    }
    op.handle_token_request(list(form.items()), TOKEN_URL, auth_header=basic_auth("demo", "s3cret"))
    with pytest.raises(OAuthError) as ei:
        op.handle_token_request(list(form.items()), TOKEN_URL, auth_header=basic_auth("demo", "s3cret"))
    assert ei.value.code == "invalid_grant" and ei.value.http_status == 400


def test_pkce_mismatch_and_bad_secret(op):
    _, code = authz(op, "verifier-one")
    with pytest.raises(OAuthError) as ei:
        op.handle_token_request(
            list(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                    "code_verifier": "wrong",
                }.items()
            ),
            TOKEN_URL,
            auth_header=basic_auth("demo", "s3cret"),
        )
    assert ei.value.code == "invalid_grant"
    with pytest.raises(OAuthError) as ei:
        op.handle_token_request(
            list(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                }.items()
            ),
            TOKEN_URL,
            auth_header=basic_auth("demo", "nope"),
        )
    assert ei.value.code == "invalid_client" and ei.value.to_response().status == 401


def test_validate_authorization_request_errors(op):
    """Unknown client / bad redirect_uri must be rendered directly, not redirected."""
    with pytest.raises(OAuthError) as ei:
        request.AuthorizationRequest.from_params(list({"client_id": "demo"}.items()))
    assert ei.value.code == "invalid_request"
    req = request.AuthorizationRequest.from_params(
        list(
            {
                "client_id": "demo",
                "response_type": "code",
                "redirect_uri": "https://evil/cb",
                "scope": "openid",
            }.items()
        )
    )
    with pytest.raises(OAuthError):
        op.validate_authorization_request(req)
    req = request.AuthorizationRequest.from_params(
        list(
            {
                "client_id": "ghost",
                "response_type": "code",
                "redirect_uri": REDIRECT_URI,
                "scope": "openid",
            }.items()
        )
    )
    with pytest.raises(OAuthError) as ei:
        op.validate_authorization_request(req)
    assert ei.value.code in ("invalid_client", "invalid_request", "unauthorized_client")


def test_authorization_request_accessors():
    req = request.AuthorizationRequest.from_params(
        list(
            {
                "client_id": "c",
                "response_type": "code id_token",
                "redirect_uri": "r",
                "scope": "openid a",
                "prompt": "login consent",
                "claims": '{"id_token": {"acr": null}}',
                "foo": "bar",
            }.items()
        )
    )
    assert req.scopes() == ["openid", "a"] and req.is_oidc()
    assert req.has_prompt("login") and not req.has_prompt("none")
    assert req.wants_code() and req.wants_id_token() and req.use_fragment()
    assert req.claims == {"id_token": {"acr": None}} and req.extra == {"foo": "bar"}
    req.validate_prompt()
    req.validate_response_type()
    d = req.to_dict()
    assert request.AuthorizationRequest.from_dict(d).client_id == "c"
    access_token_flow = request.AuthorizationRequest.from_params(
        list(
            {
                "client_id": "c",
                "response_type": "code token",
                "redirect_uri": "r",
            }.items()
        )
    )
    assert access_token_flow.use_fragment()  # front-channel tokens never default to query
    bad = request.AuthorizationRequest.from_params(
        list(
            {
                "client_id": "c",
                "response_type": "code",
                "redirect_uri": "r",
                "prompt": "none login",
                "state": "s",
            }.items()
        )
    )
    with pytest.raises(OAuthError) as ei:
        bad.validate_prompt()
    assert ei.value.state == "s"


def test_reserved_extra_claims_rejected(op):
    """grindvakt silently drops reserved id_token claims; the binding raises instead."""
    req = request.AuthorizationRequest.from_params(
        list(
            {
                "client_id": "demo",
                "response_type": "code",
                "redirect_uri": REDIRECT_URI,
                "scope": "openid",
            }.items()
        )
    )
    with pytest.raises(ValueError, match="reserved"):
        op.authorization_redirect(req, "alice", extra_claims={"sub": "x", "ok": 1})
    resp = op.authorization_redirect(req, "alice", extra_claims={"tenant": "t1"})
    assert resp.status == 302


def test_extra_claims_land_in_id_token(op):
    verifier = util.random_token(32)
    params = {
        "client_id": "demo",
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "nonce": "n",
        "code_challenge": pkce.s256_challenge(verifier),
        "code_challenge_method": "S256",
    }
    req = request.AuthorizationRequest.from_params(list(params.items()))
    resp = op.authorization_redirect(req, "alice", acr="urn:mfa", extra_claims={"tenant": {"id": 7}})
    code = code_from_redirect(resp)
    tr = op.handle_token_request(
        list(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": verifier,
            }.items()
        ),
        TOKEN_URL,
        auth_header=basic_auth("demo", "s3cret"),
    )
    claims = jwt.peek_claims_unverified(tr.id_token)
    assert claims["tenant"] == {"id": 7} and claims["acr"] == "urn:mfa" and claims["nonce"] == "n"


def test_client_credentials(op):
    tr = op.handle_token_request(
        list(
            {
                "grant_type": "client_credentials",
                "client_id": "svc",
                "client_secret": "svc-secret",
                "scope": "read",
            }.items()
        ),
        TOKEN_URL,
    )
    assert tr.scope == "read" and tr.id_token is None and tr.refresh_token is None
    with pytest.raises(OAuthError) as ei:
        op.handle_token_request(
            list(
                {
                    "grant_type": "client_credentials",
                    "client_id": "svc",
                    "client_secret": "svc-secret",
                    "scope": "admin",
                }.items()
            ),
            TOKEN_URL,
        )
    assert ei.value.code == "invalid_scope"
    with pytest.raises(OAuthError) as ei:  # demo may not use client_credentials
        op.handle_token_request(
            list({"grant_type": "client_credentials"}.items()),
            TOKEN_URL,
            auth_header=basic_auth("demo", "s3cret"),
        )
    assert ei.value.code in ("unauthorized_client", "invalid_grant")


def test_private_key_jwt(op, rp_key):
    """private_key_jwt client auth with a client assertion built by the rp module;
    the assertion's jti is single-use."""
    verifier = util.random_token(32)
    params = {
        "client_id": "jwt-rp",
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "code_challenge": pkce.s256_challenge(verifier),
        "code_challenge_method": "S256",
    }
    req = request.AuthorizationRequest.from_params(list(params.items()))
    op.validate_authorization_request(req)
    code = code_from_redirect(op.authorization_redirect(req, "bob"))
    assertion = rp.build_client_assertion(rp_key, "jwt-rp", TOKEN_URL)
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier,
        "client_assertion_type": provider.CLIENT_ASSERTION_TYPE,
        "client_assertion": assertion,
    }
    tr = op.handle_token_request(list(form.items()), TOKEN_URL)
    assert jwt.peek_claims_unverified(tr.id_token)["sub"] == "bob"
    c = op.authenticate_client(
        list(
            {
                "client_assertion_type": provider.CLIENT_ASSERTION_TYPE,
                "client_assertion": rp.build_client_assertion(rp_key, "jwt-rp", TOKEN_URL),
            }.items()
        ),
        TOKEN_URL,
    )
    assert c.client_id == "jwt-rp"
    with pytest.raises(OAuthError) as ei:  # replayed assertion
        op.authenticate_client(
            list(
                {
                    "client_assertion_type": provider.CLIENT_ASSERTION_TYPE,
                    "client_assertion": assertion,
                }.items()
            ),
            TOKEN_URL,
        )
    assert ei.value.code == "invalid_client"
    with pytest.raises(OAuthError):  # wrong audience
        op.authenticate_client(
            list(
                {
                    "client_assertion_type": provider.CLIENT_ASSERTION_TYPE,
                    "client_assertion": rp.build_client_assertion(rp_key, "jwt-rp", "https://other/token"),
                }.items()
            ),
            TOKEN_URL,
        )


def test_implicit_requires_nonce_and_fragment(op):
    req = request.AuthorizationRequest.from_params(
        list(
            {
                "client_id": "demo",
                "response_type": "id_token",
                "redirect_uri": REDIRECT_URI,
                "scope": "openid",
            }.items()
        )
    )
    with pytest.raises(OAuthError):
        op.validate_authorization_request(req)


def test_provider_requires_explicit_token_use_store(op_key, demo_client):
    from pygrindvakt import client, tokens

    with pytest.raises(ValueError, match="token_use_store is required"):
        provider.Provider(
            metadata.ProviderMetadata(ISSUER),
            op_key,
            client.InMemoryClientStore([demo_client]),
            tokens.TokenCodec("s"),
        )


def test_provider_rejects_symmetric_id_token_signing_key(demo_client):
    """OIDC MAC ID tokens require the individual client's own secret."""
    from pygrindvakt import client, tokens

    encoded = base64.urlsafe_b64encode(b"x" * 32).rstrip(b"=").decode()
    symmetric = keys.signing_key_from_jwk({"kty": "oct", "k": encoded}, alg="HS256", kid="op-hs")
    with pytest.raises(ConfigError, match="asymmetric"):
        provider.Provider(
            metadata.ProviderMetadata(ISSUER),
            symmetric,
            client.InMemoryClientStore([demo_client]),
            tokens.TokenCodec("s"),
            token_use_store=provider.InMemoryTokenUseStore(),
        )


def test_duplicate_authorization_and_token_parameters_are_rejected(op):
    pairs = [
        ("client_id", "demo"),
        ("client_id", "attacker"),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "openid"),
    ]
    with pytest.raises(OAuthError) as exc:
        request.AuthorizationRequest.from_params(pairs)
    assert exc.value.code == "invalid_request"

    resources = request.AuthorizationRequest.from_params(
        [
            ("client_id", "demo"),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("resource", "https://api-one.example"),
            ("resource", "https://api-two.example"),
        ]
    )
    assert resources.resources == ["https://api-one.example", "https://api-two.example"]
    assert "resource" not in resources.extra
    assert request.AuthorizationRequest.from_dict(resources.to_dict()).resources == resources.resources

    with pytest.raises(OAuthError) as exc:
        op.handle_token_request(
            [("grant_type", "authorization_code"), ("grant_type", "refresh_token")],
            TOKEN_URL,
        )
    assert exc.value.code == "invalid_request"

    with pytest.raises(OAuthError) as exc:
        op.authenticate_client(
            [("client_id", "demo"), ("client_secret", "s3cret")],
            TOKEN_URL,
            auth_header=basic_auth("demo", "s3cret"),
        )
    assert exc.value.code == "invalid_client"
    assert exc.value.description == "multiple client authentication methods"


def test_protocol_boundaries_reject_mappings_that_cannot_represent_duplicates(op):
    """Security-sensitive entry points require the original ordered pairs."""
    with pytest.raises(TypeError, match="mappings discard duplicate"):
        request.AuthorizationRequest.from_params({"client_id": "demo"})
    with pytest.raises(TypeError, match="mappings discard duplicate"):
        op.handle_token_request({"grant_type": "client_credentials"}, TOKEN_URL)
    with pytest.raises(TypeError, match="mappings discard duplicate"):
        op.authenticate_client({"client_id": "demo"}, TOKEN_URL)


def test_minting_revalidates_deserialized_request(op):
    req = request.AuthorizationRequest.from_params(
        list(
            {
                "client_id": "demo",
                "response_type": "code",
                "redirect_uri": REDIRECT_URI,
                "scope": "openid",
            }.items()
        )
    )
    stored = req.to_dict()
    stored["redirect_uri"] = "https://evil.example/callback"
    tampered = request.AuthorizationRequest.from_dict(stored)
    with pytest.raises(OAuthError, match="redirect_uri"):
        op.authorization_redirect(tampered, "alice")


def test_authorization_redirect_refuses_crlf_redirect_uri_even_if_registered(op_key):
    """Regression test: a registered redirect_uri with CRLF never reaches a Location header."""
    evil = REDIRECT_URI + "\r\nSet-Cookie: x=1"
    c = client.Client("crlf", client_secret="s", redirect_uris=[evil])
    crlf_op = provider.Provider(
        metadata.ProviderMetadata(ISSUER),
        op_key,
        client.InMemoryClientStore([c]),
        tokens.TokenCodec("crlf-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )
    base = request.AuthorizationRequest.from_params(
        [("client_id", "crlf"), ("response_type", "code"), ("redirect_uri", REDIRECT_URI), ("scope", "openid")]
    )
    stored = base.to_dict()
    stored["redirect_uri"] = evil
    req = request.AuthorizationRequest.from_dict(stored)
    with pytest.raises(OAuthError) as ei:
        crlf_op.authorization_redirect(req, "alice")
    assert ei.value.code == "invalid_request"


@pytest.mark.parametrize("iss_flag", [False, True])
@pytest.mark.parametrize(
    "unsafe",
    [
        REDIRECT_URI + "\\@evil.example",
        REDIRECT_URI + "\u200b",
        REDIRECT_URI + "\u202e",
        "https://good.example@evil.example/cb",
    ],
    ids=["backslash", "zero-width", "bidi", "userinfo"],
)
def test_registered_unsafe_redirect_uri_never_reaches_a_location_header(op_key, unsafe, iss_flag):
    """Core accepts these registered URIs; the binding's redirect_uri rules must stop them
    on both render paths, with and without the RFC 9207 flag."""
    c = client.Client("unsafe", client_secret="s", redirect_uris=[unsafe])
    unsafe_op = provider.Provider(
        metadata.ProviderMetadata(ISSUER),
        op_key,
        client.InMemoryClientStore([c]),
        tokens.TokenCodec("unsafe-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
        authorization_response_iss=iss_flag,
    )
    base = request.AuthorizationRequest.from_params(
        [("client_id", "unsafe"), ("response_type", "code"), ("redirect_uri", REDIRECT_URI), ("scope", "openid")]
    )
    stored = base.to_dict()
    stored["redirect_uri"] = unsafe
    req = request.AuthorizationRequest.from_dict(stored)
    with pytest.raises(OAuthError) as ei:
        unsafe_op.authorization_redirect(req, "alice")
    assert ei.value.code == "invalid_request" and "evil" not in str(ei.value)
    with pytest.raises(OAuthError) as ei:
        unsafe_op.authorization_error_redirect(req, OAuthError("access_denied", "no", "st"))
    assert ei.value.code == "invalid_request" and "evil" not in str(ei.value)


def test_token_bearing_query_mode_and_empty_subject_are_rejected(op):
    req = request.AuthorizationRequest.from_params(
        list(
            {
                "client_id": "demo",
                "response_type": "code id_token",
                "redirect_uri": REDIRECT_URI,
                "scope": "openid",
                "nonce": "n",
                "response_mode": "query",
            }.items()
        )
    )
    with pytest.raises(OAuthError):
        op.validate_authorization_request(req)

    code_req = request.AuthorizationRequest.from_params(
        list(
            {
                "client_id": "demo",
                "response_type": "code",
                "redirect_uri": REDIRECT_URI,
                "scope": "openid",
            }.items()
        )
    )
    with pytest.raises(OAuthError, match="subject"):
        op.authorization_redirect(code_req, "")


def test_hybrid_and_implicit_responses_include_oidc_hashes(op_key):
    from pygrindvakt import client, tokens

    c = client.Client(
        "flows",
        client_secret="secret",
        redirect_uris=[REDIRECT_URI],
        response_types=[
            "code id_token",
            "id_token token",
            "code token",
            "code id_token token",
        ],
        scope="openid profile",
    )
    flow_op = provider.Provider(
        metadata.ProviderMetadata(ISSUER),
        op_key,
        client.InMemoryClientStore([c]),
        tokens.TokenCodec("flow-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )

    hybrid = request.AuthorizationRequest.from_params(
        list(
            {
                "client_id": "flows",
                "response_type": "code id_token",
                "redirect_uri": REDIRECT_URI,
                "scope": "openid",
                "nonce": "n",
            }.items()
        )
    )
    location = flow_op.authorization_redirect(hybrid, "alice").header("location")
    values = parse_qs(urlparse(location).fragment)
    claims = jwt.peek_claims_unverified(values["id_token"][0])
    expected_c_hash = (
        base64.urlsafe_b64encode(hashlib.sha256(values["code"][0].encode()).digest()[:16]).rstrip(b"=").decode()
    )
    assert claims["c_hash"] == expected_c_hash

    implicit = request.AuthorizationRequest.from_params(
        list(
            {
                "client_id": "flows",
                "response_type": "id_token token",
                "redirect_uri": REDIRECT_URI,
                "scope": "openid",
                "nonce": "n",
            }.items()
        )
    )
    location = flow_op.authorization_redirect(implicit, "alice").header("location")
    values = parse_qs(urlparse(location).fragment)
    assert values["token_type"] == ["Bearer"] and int(values["expires_in"][0]) > 0
    claims = jwt.peek_claims_unverified(values["id_token"][0])
    expected_at_hash = (
        base64.urlsafe_b64encode(hashlib.sha256(values["access_token"][0].encode()).digest()[:16]).rstrip(b"=").decode()
    )
    assert claims["at_hash"] == expected_at_hash

    for response_type in ["code token", "code id_token token"]:
        req = request.AuthorizationRequest.from_params(
            list(
                {
                    "client_id": "flows",
                    "response_type": response_type,
                    "redirect_uri": REDIRECT_URI,
                    "scope": "openid",
                    "nonce": "n",
                }.items()
            )
        )
        response = flow_op.authorization_redirect(req, "alice")
        assert response.status == 302 and urlparse(response.header("location")).fragment

    # RFC 6749 section 3.1.1 defines response_type as an unordered list.
    reordered = request.AuthorizationRequest.from_params(
        list(
            {
                "client_id": "flows",
                "response_type": "token id_token",
                "redirect_uri": REDIRECT_URI,
                "scope": "openid",
                "nonce": "n",
            }.items()
        )
    )
    assert flow_op.authorization_redirect(reordered, "alice").status == 302


def test_non_openid_flow_omits_id_token_and_userinfo_and_claims_are_scope_filtered(op, op_key):
    from pygrindvakt import client, tokens

    c = client.Client("oauth", client_secret="secret", redirect_uris=[REDIRECT_URI], scope="email")
    oauth_op = provider.Provider(
        metadata.ProviderMetadata(ISSUER),
        op_key,
        client.InMemoryClientStore([c]),
        tokens.TokenCodec("oauth-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )
    req = request.AuthorizationRequest.from_params(
        list(
            {
                "client_id": "oauth",
                "response_type": "code",
                "redirect_uri": REDIRECT_URI,
                "scope": "email",
            }.items()
        )
    )
    code = code_from_redirect(oauth_op.authorization_redirect(req, "alice", {"email": ["a@b"]}))
    tr = oauth_op.handle_token_request(
        list(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
            }.items()
        ),
        TOKEN_URL,
        auth_header=basic_auth("oauth", "secret"),
    )
    assert tr.id_token is None
    with pytest.raises(OAuthError, match="openid scope"):
        oauth_op.userinfo(tr.access_token)

    oidc_service = client.Client(
        "oidc-service",
        client_secret="secret",
        grant_types=["client_credentials"],
        token_endpoint_auth_method="client_secret_post",
        scope="openid email",
    )
    service_op = provider.Provider(
        metadata.ProviderMetadata(ISSUER),
        op_key,
        client.InMemoryClientStore([oidc_service]),
        tokens.TokenCodec("service-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )
    with pytest.raises(OAuthError, match="end-user authorization"):
        service_op.handle_token_request(
            list(
                {
                    "grant_type": "client_credentials",
                    "client_id": "oidc-service",
                    "client_secret": "secret",
                    "scope": "openid",
                }.items()
            ),
            TOKEN_URL,
        )

    req = request.AuthorizationRequest.from_params(
        list(
            {
                "client_id": "demo",
                "response_type": "code",
                "redirect_uri": REDIRECT_URI,
                "scope": "openid",
                "nonce": "n",
            }.items()
        )
    )
    code = code_from_redirect(
        op.authorization_redirect(req, "alice", {"email": ["a@b"], "name": ["Alice"], "tenant": ["example"]})
    )
    tr = op.handle_token_request(
        list(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
            }.items()
        ),
        TOKEN_URL,
        auth_header=basic_auth("demo", "s3cret"),
    )
    claims = jwt.peek_claims_unverified(tr.id_token)
    assert "email" not in claims and "name" not in claims and claims["tenant"] == "example"
    assert op.userinfo(tr.access_token) == {"sub": "alice", "tenant": "example"}


def test_explicit_end_session_endpoint_is_advertised_and_warns(op, op_key):
    assert op.discovery_document()["subject_types_supported"] == ["public"]
    md = metadata.ProviderMetadata(ISSUER)
    from pygrindvakt import client, tokens

    md.set_extra_field("end_session_endpoint", f"{ISSUER}/logout")
    assert md.end_session_endpoint == f"{ISSUER}/logout"
    with pytest.warns(UserWarning, match="does not implement end_session_endpoint"):
        advertising = provider.Provider(
            md,
            op_key,
            client.InMemoryClientStore([]),
            tokens.TokenCodec("s"),
            token_use_store=provider.InMemoryTokenUseStore(),
        )
    assert advertising.discovery_document()["end_session_endpoint"] == f"{ISSUER}/logout"
    with pytest.raises(ValueError, match="reserved"):
        md.extra = {"issuer": "https://evil.example"}


def _build(md, op_key):
    from pygrindvakt import client, tokens

    return provider.Provider(
        md,
        op_key,
        client.InMemoryClientStore([]),
        tokens.TokenCodec("s"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )


def test_provider_warns_once_listing_all_unimplemented_members(op_key):
    md = metadata.ProviderMetadata(ISSUER)
    md.revocation_endpoint = f"{ISSUER}/revoke"
    md.introspection_endpoint = f"{ISSUER}/introspect"
    md.pushed_authorization_request_endpoint = f"{ISSUER}/par"
    md.check_session_iframe = f"{ISSUER}/iframe"
    md.frontchannel_logout_supported = True
    md.backchannel_logout_supported = True
    md.require_pushed_authorization_requests = True
    md.end_session_endpoint = f"{ISSUER}/logout"
    with pytest.warns(UserWarning) as rec:
        _build(md, op_key)
    assert len(rec) == 1
    msg = str(rec[0].message)
    for name in (
        "end_session_endpoint",
        "revocation_endpoint",
        "introspection_endpoint",
        "pushed_authorization_request_endpoint",
        "check_session_iframe",
        "frontchannel_logout_supported",
        "backchannel_logout_supported",
        "require_pushed_authorization_requests",
    ):
        assert name in msg
    assert "claim you are making about your own front end" in msg
    assert rec[0].filename == __file__


def test_provider_silent_without_unimplemented_members(op_key):
    import warnings

    md = metadata.ProviderMetadata(ISSUER)
    md.frontchannel_logout_supported = False
    md.backchannel_logout_supported = False
    md.require_pushed_authorization_requests = False
    md.service_documentation = f"{ISSUER}/docs"
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        _build(md, op_key)
    assert caught == []


def test_metadata_setters_do_not_warn():
    import warnings

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        md = metadata.ProviderMetadata(ISSUER)
        md.end_session_endpoint = f"{ISSUER}/logout"
        md.set_extra_field("revocation_endpoint", f"{ISSUER}/revoke")
    assert caught == []


def test_token_lifetimes_and_metadata_customisation(op_key, demo_client):
    from pygrindvakt import client, tokens

    md = metadata.ProviderMetadata("https://issuer.example", "https://issuer.example/oidc")
    assert md.token_endpoint == "https://issuer.example/oidc/token"
    md.scopes_supported = ["openid"]
    md.set_extra_field("custom", {"x": 1})
    md.claims_parameter_supported = True
    lt = provider.TokenLifetimes(code_ttl=5, access_token_ttl=7)
    p = provider.Provider(
        md,
        op_key,
        client.InMemoryClientStore([demo_client]),
        tokens.TokenCodec("s"),
        lifetimes=lt,
        token_use_store=provider.InMemoryTokenUseStore(),
        client_assertion_max_age=10,
    )
    d = p.discovery_document()
    assert d["custom"] == {"x": 1} and d["scopes_supported"] == ["openid"]
    assert d["claims_parameter_supported"] is False
    assert d["id_token_signing_alg_values_supported"] == ["ES256"]
    assert p.lifetimes.access_token_ttl == 7 and p.lifetimes.refresh_token_ttl == 2_592_000
    assert metadata.ProviderMetadata.from_dict(d).token_endpoint == md.token_endpoint
    assert isinstance(p.token_use_store, provider.InMemoryTokenUseStore)


def test_flatten_claims():
    assert provider.flatten_claims({"email_verified": ["true"], "groups": ["a", "b"], "name": ["N"]}) == {
        "email_verified": True,
        "groups": ["a", "b"],
        "name": "N",
    }
    assert "sub" in provider.RESERVED_ID_TOKEN_CLAIMS


def test_userinfo_rejects_garbage_and_expired(op, op_key):
    with pytest.raises(OAuthError) as ei:
        op.userinfo("not-a-token")
    assert ei.value.code in ("invalid_request", "access_denied", "invalid_grant")


def test_threads_do_not_deadlock(op):
    """The runtime bridge releases the GIL; many threads can drive the provider."""
    from concurrent.futures import ThreadPoolExecutor

    def one(i):
        v = util.random_token(32)
        _, code = authz(op, v)
        tr = op.handle_token_request(
            list(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                    "code_verifier": v,
                }.items()
            ),
            TOKEN_URL,
            auth_header=basic_auth("demo", "s3cret"),
        )
        return op.userinfo(tr.access_token)["sub"]

    with ThreadPoolExecutor(8) as ex:
        assert set(ex.map(one, range(40))) == {"alice"}


def test_in_memory_token_use_store_direct():
    s = provider.InMemoryTokenUseStore()
    assert s.consume("h", 60) is True
    assert s.consume("h", 60) is False


@pytest.mark.redis
def test_redis_store(redis_url):
    s = provider.RedisStore(redis_url, key_prefix="pygrindvakt-test:")
    h = util.random_token(8)
    assert s.consume(h, 5) is True
    assert s.consume(h, 5) is False
    assert provider.RedisStore.DEFAULT_KEY_PREFIX == "grindvakt:token-use:"


def test_failing_constructor_does_not_warn(op_key):
    import warnings

    from pygrindvakt import tokens

    md = metadata.ProviderMetadata(ISSUER)
    md.end_session_endpoint = f"{ISSUER}/logout"
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with pytest.raises(TypeError):
            provider.Provider(
                md,
                op_key,
                object(),
                tokens.TokenCodec("s"),
                token_use_store=provider.InMemoryTokenUseStore(),
            )
        with pytest.raises(ValueError, match="token_use_store"):
            from pygrindvakt import client

            provider.Provider(md, op_key, client.InMemoryClientStore([]), tokens.TokenCodec("s"))
    assert caught == []


def test_provider_warning_escalates_under_warnings_as_errors(op_key):
    """-W error::UserWarning must turn the unimplemented-member warning into a failure."""
    import warnings

    md = metadata.ProviderMetadata(ISSUER)
    md.require_pushed_authorization_requests = True
    with warnings.catch_warnings():
        warnings.simplefilter("error", UserWarning)
        with pytest.raises(UserWarning, match="require_pushed_authorization_requests"):
            _build(md, op_key)


def test_jwks_document_never_contains_oct_key(op):
    """A Provider cannot hold a symmetric key (HS* is refused at construction,
    see test_provider_rejects_symmetric_id_token_signing_key), so its JWKS
    document is asymmetric and emits no warning (ADR 0006)."""
    import warnings

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        doc = op.jwks_document()
    assert caught == []
    assert doc["keys"] and all(k["kty"] != "oct" for k in doc["keys"])


def test_code_bound_to_registration():
    """A code is bound to the registration fingerprint: a changed client -> invalid_grant."""
    demo = client.Client(
        "demo",
        client_secret="s3cret",
        redirect_uris=[REDIRECT_URI],
        grant_types=["authorization_code", "refresh_token"],
        client_name="Demo RP",
    )
    store = client.InMemoryClientStore([demo])
    codec = tokens.TokenCodec("op-secret")
    key = keys.signing_key_from_jwk(keys.generate_ec_jwk("P-256"), alg="ES256", kid="op-1")
    op = provider.Provider(
        metadata.ProviderMetadata(ISSUER),
        key,
        store,
        codec,
        token_use_store=provider.InMemoryTokenUseStore(),
    )
    _req, code = authz(op)
    digest = codec.open_code(code).registration_digest
    assert isinstance(digest, str) and digest
    store.put(
        client.Client(
            "demo",
            client_secret="s3cret",
            redirect_uris=[REDIRECT_URI],
            grant_types=["authorization_code", "refresh_token"],
            client_name="Renamed",
        )
    )
    with pytest.raises(OAuthError) as ei:
        op.handle_token_request(
            list({"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI}.items()),
            TOKEN_URL,
            auth_header=basic_auth("demo", "s3cret"),
        )
    assert ei.value.code == "invalid_grant"


def _self_seal_setup(digest_from_client):
    """OP that seals its own code; returns (op, store, codec, code)."""
    kw = {
        "client_secret": "s3cret",
        "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "client_name": "Demo RP",
    }
    demo = client.Client("demo", **kw)
    store = client.InMemoryClientStore([demo])
    codec = tokens.TokenCodec("op-secret")
    key = keys.signing_key_from_jwk(keys.generate_ec_jwk("P-256"), alg="ES256", kid="op-1")
    op = provider.Provider(
        metadata.ProviderMetadata(ISSUER),
        key,
        store,
        codec,
        token_use_store=provider.InMemoryTokenUseStore(),
    )
    now = int(time.time())
    with contextlib.nullcontext() if digest_from_client else pytest.warns(FutureWarning):
        payload = tokens.AuthCodePayload(
            client_id="demo",
            redirect_uri=REDIRECT_URI,
            scope="openid",
            sub="alice",
            auth_time=now,
            exp=now + 600,
            registration_digest=demo.registration_fingerprint() if digest_from_client else None,
        )
    code = codec.seal_code(payload)
    return op, store, code


def _redeem(op, code):
    return op.handle_token_request(
        list({"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI}.items()),
        TOKEN_URL,
        auth_header=basic_auth("demo", "s3cret"),
    )


def _rotated_client():
    return client.Client(
        "demo",
        client_secret="s3cret",
        redirect_uris=[REDIRECT_URI],
        grant_types=["authorization_code", "refresh_token"],
        client_name="Renamed",
    )


def test_self_sealed_code_with_fingerprint_unchanged_registration_succeeds():
    op, _store, code = _self_seal_setup(True)
    assert _redeem(op, code) is not None


def test_self_sealed_code_with_fingerprint_rejects_changed_registration():
    op, store, code = _self_seal_setup(True)
    store.put(_rotated_client())
    with pytest.raises(OAuthError) as ei:
        _redeem(op, code)
    assert ei.value.code == "invalid_grant"


def test_self_sealed_code_without_digest_skips_registration_check():
    """Documents core behavior: digest=None silently skips the binding check.

    The docs warn about this; self-sealing OPs must pass
    client.registration_fingerprint().
    """
    op, store, code = _self_seal_setup(False)
    store.put(_rotated_client())
    assert _redeem(op, code) is not None


def _pinned_provider(op_key, clients):
    return provider.Provider(
        metadata.ProviderMetadata(ISSUER),
        op_key,
        client.InMemoryClientStore(clients),
        tokens.TokenCodec("op-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )


def test_registered_token_endpoint_auth_signing_alg_is_enforced(op_key, rp_key):
    """A client registered with token_endpoint_auth_signing_alg only authenticates
    with that algorithm (and a kid); other algorithms fail with invalid_client."""
    es_jwks = rp_key.to_public_jwks()
    ps_key = keys.signing_key_from_jwk(keys.generate_rsa_jwk(2048), alg="RS256", kid="rsa-1")
    both = {"keys": es_jwks["keys"] + ps_key.to_public_jwks()["keys"]}

    def mk(alg):
        return client.Client(
            "pinned",
            redirect_uris=[REDIRECT_URI],
            token_endpoint_auth_method="private_key_jwt",
            jwks=both,
            response_policy={"token_endpoint_auth_signing_alg": alg},
        )

    def auth(op, key):
        return op.authenticate_client(
            [
                ("client_assertion_type", provider.CLIENT_ASSERTION_TYPE),
                ("client_assertion", rp.build_client_assertion(key, "pinned", TOKEN_URL)),
            ],
            TOKEN_URL,
        )

    op = _pinned_provider(op_key, [mk("ES256")])
    assert auth(op, rp_key).client_id == "pinned"
    with pytest.raises(OAuthError) as ei:  # RS256 assertion, ES256 pinned
        auth(op, ps_key)
    assert ei.value.code == "invalid_client"

    # Same keys without a pin: both algorithms are accepted.
    unpinned = _pinned_provider(
        op_key,
        [
            client.Client(
                "pinned",
                redirect_uris=[REDIRECT_URI],
                token_endpoint_auth_method="private_key_jwt",
                jwks=both,
            )
        ],
    )
    assert auth(unpinned, ps_key).client_id == "pinned"

    # The pin travels through the dict / from_dict path too.
    via_dict = _pinned_provider(op_key, [mk("ES256").to_dict()])
    with pytest.raises(OAuthError) as ei:
        auth(via_dict, ps_key)
    assert ei.value.code == "invalid_client"


def test_registered_id_token_encryption_yields_jwe(op_key):
    """A client registered for ID token encryption receives a 5-part JWE."""
    enc_jwk = keys.generate_ec_jwk("P-256")
    enc_jwk["use"] = "enc"
    enc_jwk["kid"] = "enc-1"
    c = client.Client(
        "enc-rp",
        client_secret="s3cret",
        redirect_uris=[REDIRECT_URI],
        jwks={"keys": [enc_jwk]},
        response_policy={"id_token_encrypted_response_alg": "ECDH-ES"},
    )
    op = _pinned_provider(op_key, [c])
    verifier = util.random_token(32)
    req = request.AuthorizationRequest.from_params(
        [
            ("client_id", "enc-rp"),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
            ("nonce", "n"),
            ("code_challenge", pkce.s256_challenge(verifier)),
            ("code_challenge_method", "S256"),
        ]
    )
    op.validate_authorization_request(req)
    code = code_from_redirect(op.authorization_redirect(req, "bob"))
    tr = op.handle_token_request(
        [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", verifier),
        ],
        TOKEN_URL,
        auth_header=basic_auth("enc-rp", "s3cret"),
    )
    assert tr.id_token.count(".") == 4


# Pins the contract in the docs/api/tokens.rst warning on ``userinfo_claims``:
# None and omitted both inherit ``claims``; only ``{}`` withholds.
_OMIT = object()


def _uc_kwargs(userinfo_claims):
    return {} if userinfo_claims is _OMIT else {"userinfo_claims": userinfo_claims}


def _uc_op():
    demo = client.Client(
        "demo",
        client_secret="s3cret",
        redirect_uris=[REDIRECT_URI],
        grant_types=["authorization_code", "refresh_token"],
    )
    codec = tokens.TokenCodec("op-secret")
    key = keys.signing_key_from_jwk(keys.generate_ec_jwk("P-256"), alg="ES256", kid="op-1")
    op = provider.Provider(
        metadata.ProviderMetadata(ISSUER),
        key,
        client.InMemoryClientStore([demo]),
        codec,
        token_use_store=provider.InMemoryTokenUseStore(),
    )
    return op, codec, demo


_UC_CASES = [
    pytest.param(_OMIT, True, id="omitted"),
    pytest.param(None, True, id="none"),
    pytest.param({}, False, id="empty"),
]


@pytest.mark.parametrize(("userinfo_claims", "released"), _UC_CASES)
def test_code_userinfo_claims_none_and_omitted_inherit_claims(userinfo_claims, released):
    op, codec, demo = _uc_op()
    now = int(time.time())
    code = codec.seal_code(
        tokens.AuthCodePayload(
            client_id="demo",
            redirect_uri=REDIRECT_URI,
            scope="openid email",
            sub="alice",
            auth_time=now,
            exp=now + 600,
            claims={"email": "alice@example.com"},
            registration_digest=demo.registration_fingerprint(),
            **_uc_kwargs(userinfo_claims),
        )
    )
    ui = op.userinfo(_redeem(op, code).access_token)
    if released:
        assert ui == {"sub": "alice", "email": "alice@example.com"}
    else:
        assert ui == {"sub": "alice"}


@pytest.mark.parametrize(("userinfo_claims", "released"), _UC_CASES)
def test_refresh_userinfo_claims_none_and_omitted_inherit_claims(userinfo_claims, released):
    op, codec, _demo = _uc_op()
    now = int(time.time())
    rt = codec.seal_refresh_token(
        tokens.RefreshTokenPayload(
            client_id="demo",
            sub="alice",
            scope="openid email",
            auth_time=now,
            exp=now + 600,
            claims={"email": "alice@example.com"},
            **_uc_kwargs(userinfo_claims),
        )
    )
    tr = op.handle_token_request(
        list({"grant_type": "refresh_token", "refresh_token": rt}.items()),
        TOKEN_URL,
        auth_header=basic_auth("demo", "s3cret"),
    )
    ui = op.userinfo(tr.access_token)
    if released:
        assert ui == {"sub": "alice", "email": "alice@example.com"}
    else:
        assert ui == {"sub": "alice"}


# ---- AuthorizedClaims / authorization_redirect_with_authorized_claims ----


def _ac_request(scope="openid email", response_type="code", **extra):
    params = {
        "client_id": "demo",
        "response_type": response_type,
        "redirect_uri": REDIRECT_URI,
        "scope": scope,
        "state": "st",
        "nonce": "n1",
    }
    params.update(extra)
    return request.AuthorizationRequest.from_params(list(params.items()))


def _ac_code(op, claims, scope="openid email", **kw):
    resp = op.authorization_redirect_with_authorized_claims(_ac_request(scope), "alice", claims, **kw)
    return code_from_redirect(resp)


_SPLIT = {"id_token": {"name": "A"}, "userinfo": {"email": "a@x", "email_verified": True}}


def test_authorized_claims_split_release():
    op, _codec, _demo = _uc_op()
    ac = provider.AuthorizedClaims(**_SPLIT)
    tr = _redeem(op, _ac_code(op, ac))
    idc = jwt.peek_claims_unverified(tr.id_token)
    assert idc["name"] == "A" and "email" not in idc and "email_verified" not in idc
    assert op.userinfo(tr.access_token) == {"sub": "alice", "email": "a@x", "email_verified": True}


def test_authorized_claims_empty_userinfo_releases_only_sub():
    op, _codec, _demo = _uc_op()
    ac = provider.AuthorizedClaims(id_token={"name": "A"}, userinfo={})
    tr = _redeem(op, _ac_code(op, ac))
    assert op.userinfo(tr.access_token) == {"sub": "alice"}


def test_authorized_claims_code_seals_digest_and_userinfo_claims():
    op, codec, demo = _uc_op()
    payload = codec.open_code(_ac_code(op, provider.AuthorizedClaims(**_SPLIT)))
    assert payload.registration_digest == demo.registration_fingerprint()
    assert payload.userinfo_claims == {"email": "a@x", "email_verified": True}
    empty = codec.open_code(_ac_code(op, provider.AuthorizedClaims(id_token={}, userinfo={})))
    assert empty.userinfo_claims == {}


def test_authorized_claims_refresh_keeps_split():
    op, _codec, _demo = _uc_op()
    tr = _redeem(op, _ac_code(op, provider.AuthorizedClaims(**_SPLIT)))
    tr2 = op.handle_token_request(
        list({"grant_type": "refresh_token", "refresh_token": tr.refresh_token}.items()),
        TOKEN_URL,
        auth_header=basic_auth("demo", "s3cret"),
    )
    idc = jwt.peek_claims_unverified(tr2.id_token)
    assert idc["name"] == "A" and "email" not in idc
    assert op.userinfo(tr2.access_token) == {"sub": "alice", "email": "a@x", "email_verified": True}


def test_authorized_claims_implicit_id_token_token(op_key):
    c = client.Client(
        "flows",
        client_secret="secret",
        redirect_uris=[REDIRECT_URI],
        response_types=["id_token token"],
        scope="openid email",
    )
    flow_op = provider.Provider(
        metadata.ProviderMetadata(ISSUER),
        op_key,
        client.InMemoryClientStore([c]),
        tokens.TokenCodec("flow-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )
    req = request.AuthorizationRequest.from_params(
        list(
            {
                "client_id": "flows",
                "response_type": "id_token token",
                "redirect_uri": REDIRECT_URI,
                "scope": "openid email",
                "nonce": "n",
            }.items()
        )
    )
    resp = flow_op.authorization_redirect_with_authorized_claims(req, "alice", provider.AuthorizedClaims(**_SPLIT))
    values = parse_qs(urlparse(resp.header("location")).fragment)
    idc = jwt.peek_claims_unverified(values["id_token"][0])
    assert idc["name"] == "A" and "email" not in idc
    assert flow_op.userinfo(values["access_token"][0]) == {"sub": "alice", "email": "a@x", "email_verified": True}


def test_authorized_claims_validation():
    ac = provider.AuthorizedClaims(**_SPLIT)
    assert ac.id_token == {"name": "A"} and ac.userinfo == _SPLIT["userinfo"]
    ac.id_token["x"] = 1  # fresh dict per access
    assert ac.id_token == {"name": "A"}
    assert "a@x" not in repr(ac) and "email" in repr(ac)
    for name in ["sub", "iss", "nonce", "acr", "auth_time", "at_hash"]:
        with pytest.raises(ValueError, match="reserved"):
            provider.AuthorizedClaims(id_token={name: "x"}, userinfo={})
        with pytest.raises(ValueError, match="reserved"):
            provider.AuthorizedClaims(id_token={}, userinfo={name: "x"})
    with pytest.raises(TypeError):
        provider.AuthorizedClaims(id_token=None, userinfo={})
    with pytest.raises(TypeError):
        provider.AuthorizedClaims(id_token={}, userinfo=None)
    with pytest.raises(TypeError):
        provider.AuthorizedClaims(id_token={})  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        provider.AuthorizedClaims({}, {})  # type: ignore[misc]


def test_authorized_claims_applies_no_scope_filter():
    op, _codec, _demo = _uc_op()
    ac = provider.AuthorizedClaims(id_token={"dept": "x"}, userinfo={"phone_number": "1"})
    tr = _redeem(op, _ac_code(op, ac, scope="openid"))
    assert jwt.peek_claims_unverified(tr.id_token)["dept"] == "x"
    assert op.userinfo(tr.access_token) == {"sub": "alice", "phone_number": "1"}


def test_authorized_claims_acr_and_auth_time():
    op, _codec, _demo = _uc_op()
    ac = provider.AuthorizedClaims(id_token={}, userinfo={})
    tr = _redeem(op, _ac_code(op, ac, acr="urn:acr:2", auth_time=1_700_000_000))
    idc = jwt.peek_claims_unverified(tr.id_token)
    assert idc["acr"] == "urn:acr:2" and idc["auth_time"] == 1_700_000_000


def test_authorized_claims_pairwise_client_refused(op_key):
    c = client.Client(
        "pw",
        client_secret="s",
        redirect_uris=[REDIRECT_URI],
        subject_type="pairwise",
    )
    pw_op = provider.Provider(
        metadata.ProviderMetadata(ISSUER),
        op_key,
        client.InMemoryClientStore([c]),
        tokens.TokenCodec("pw-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )
    req = request.AuthorizationRequest.from_params(
        [("client_id", "pw"), ("response_type", "code"), ("redirect_uri", REDIRECT_URI), ("scope", "openid")]
    )
    with pytest.raises(OAuthError) as ei:
        pw_op.authorization_redirect_with_authorized_claims(
            req, "alice", provider.AuthorizedClaims(id_token={}, userinfo={})
        )
    assert ei.value.code == "unauthorized_client"


def test_authorized_claims_refuses_crlf_redirect_uri(op_key):
    evil = REDIRECT_URI + "\r\nSet-Cookie: x=1"
    c = client.Client("crlf", client_secret="s", redirect_uris=[evil])
    crlf_op = provider.Provider(
        metadata.ProviderMetadata(ISSUER),
        op_key,
        client.InMemoryClientStore([c]),
        tokens.TokenCodec("crlf-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )
    base = request.AuthorizationRequest.from_params(
        [("client_id", "crlf"), ("response_type", "code"), ("redirect_uri", REDIRECT_URI), ("scope", "openid")]
    )
    stored = base.to_dict()
    stored["redirect_uri"] = evil
    req = request.AuthorizationRequest.from_dict(stored)
    with pytest.raises(OAuthError) as ei:
        crlf_op.authorization_redirect_with_authorized_claims(
            req, "alice", provider.AuthorizedClaims(id_token={}, userinfo={})
        )
    assert ei.value.code == "invalid_request"


# --- Provider.signed_userinfo -------------------------------------------------


def _openid_token(op, scope="openid email", client_id="demo", secret="s3cret"):
    verifier = util.random_token(32)
    req = request.AuthorizationRequest.from_params(
        [
            ("client_id", client_id),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", scope),
            ("nonce", "n"),
            ("code_challenge", pkce.s256_challenge(verifier)),
            ("code_challenge_method", "S256"),
        ]
    )
    op.validate_authorization_request(req)
    resp = op.authorization_redirect(req, "alice", {"email": ["alice@example.com"]})
    return op.handle_token_request(
        [
            ("grant_type", "authorization_code"),
            ("code", code_from_redirect(resp)),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", verifier),
        ],
        TOKEN_URL,
        auth_header=basic_auth(client_id, secret),
    )


class _JwtUserinfoClient:
    def __init__(self, body):
        self.body = body

    def get(self, url, headers=None):
        return 200, self.body.encode(), "application/jwt"

    def post_form(self, url, form, headers):
        return 200, self.body.encode(), "application/jwt"


def test_signed_userinfo_round_trips_through_rp(op):
    tr = _openid_token(op)
    jws = op.signed_userinfo(tr.access_token)
    assert jws.count(".") == 2
    assert jwt.peek_header(jws)["typ"] == "userinfo+jwt"
    claims = rp.fetch_userinfo(
        _JwtUserinfoClient(jws),
        "https://op.example.com/userinfo",
        tr.access_token,
        "alice",
        ISSUER,
        trust="typed",
        typ="userinfo+jwt",
        jwks=op.jwks_document(),
        client_id="demo",
        allowed_algorithms=["ES256"],
    )
    assert claims["sub"] == "alice" and claims["email"] == "alice@example.com"
    assert claims["iss"] == ISSUER and claims["aud"] == "demo"


def test_signed_userinfo_exp_capped_at_five_minutes(op):
    tr = _openid_token(op)
    claims = jwt.peek_claims_unverified(op.signed_userinfo(tr.access_token))
    assert claims["exp"] <= claims["iat"] + 300


def test_signed_userinfo_encrypted_for_registered_client(op_key):
    enc_jwk = keys.generate_ec_jwk("P-256")
    enc_jwk["use"] = "enc"
    enc_jwk["kid"] = "enc-1"
    c = client.Client(
        "demo",
        client_secret="s3cret",
        redirect_uris=[REDIRECT_URI],
        jwks={"keys": [enc_jwk]},
        response_policy={"userinfo_encrypted_response_alg": "ECDH-ES"},
    )
    op = _pinned_provider(op_key, [c])
    tr = _openid_token(op)
    jwe = op.signed_userinfo(tr.access_token)
    assert jwe.count(".") == 4
    header = json.loads(base64.urlsafe_b64decode(jwe.split(".")[0] + "=="))
    assert header["alg"] == "ECDH-ES" and header["enc"] == "A128CBC-HS256"
    # The plain endpoint is unaffected.
    assert isinstance(op.userinfo(tr.access_token), dict)
    assert op.userinfo(tr.access_token)["sub"] == "alice"


def test_signed_userinfo_rejects_bad_tokens(op):
    tr = _openid_token(op, scope="email", client_id="demo")  # no openid scope
    with pytest.raises(OAuthError) as ei:
        op.signed_userinfo(tr.access_token)
    with pytest.raises(OAuthError) as ei2:
        op.userinfo(tr.access_token)
    assert ei.value.code == ei2.value.code == "access_denied"
    with pytest.raises(OAuthError) as ei3:
        op.signed_userinfo("not-a-token")
    with pytest.raises(OAuthError) as ei4:
        op.userinfo("not-a-token")
    assert ei3.value.code == ei4.value.code == "access_denied"


def test_signed_userinfo_client_removed_is_invalid_grant(op_key, demo_client):
    class Store:
        def __init__(self, *cs):
            self.d = {c.client_id: c for c in cs}

        def get(self, client_id):
            return self.d.get(client_id)

        def put(self, c):
            self.d[c.client_id] = c

        def put_with_ttl(self, c, ttl):
            self.d[c.client_id] = c

    store = Store(demo_client)
    op = provider.Provider(
        metadata.ProviderMetadata(ISSUER),
        op_key,
        store,
        tokens.TokenCodec("op-secret"),
        token_use_store=provider.InMemoryTokenUseStore(),
    )
    tr = _openid_token(op)
    assert op.signed_userinfo(tr.access_token).count(".") == 2
    del store.d["demo"]
    with pytest.raises(OAuthError) as ei:
        op.signed_userinfo(tr.access_token)
    assert ei.value.code == "invalid_grant"


def test_consume_request_id_first_use_then_replay(op):
    exp = int(time.time()) + 300
    assert op.consume_request_id("demo", "jti-1", exp) is None
    with pytest.raises(OAuthError) as exc:
        op.consume_request_id("demo", "jti-1", exp)
    assert exc.value.code == "invalid_grant"
    # Same jti for another client is independent.
    assert op.consume_request_id("svc", "jti-1", exp) is None


@pytest.mark.parametrize("jti", ["", "x" * 513])
def test_consume_request_id_rejects_bad_jti(op, jti):
    with pytest.raises(OAuthError) as exc:
        op.consume_request_id("demo", jti, int(time.time()) + 300)
    assert exc.value.code == "invalid_request"


def test_consume_request_id_accepts_512_byte_jti(op):
    assert op.consume_request_id("demo", "x" * 512, int(time.time()) + 300) is None


def test_consume_request_id_rejects_past_expiry(op):
    with pytest.raises(OAuthError) as exc:
        op.consume_request_id("demo", "jti-old", int(time.time()) - 1)
    assert exc.value.code == "invalid_request"
