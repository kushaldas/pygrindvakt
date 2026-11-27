"""DPoP (RFC 9449): proof validation, replay, nonce challenge, resource binding.

Proofs are built in Python with pygrindvakt.jwt.sign over a fresh ES256 key,
exactly as a client library would.
"""

import base64
import hashlib
import time

import pytest
from conftest import TOKEN_URL, USERINFO_URL
from pygrindvakt import (
    DpopInvalidError,
    DpopNonceRequiredError,
    DpopReplayError,
    DpopServerError,
    OAuthError,
    dpop,
    keys,
    util,
)


def make_proof(key, htm, htu, nonce=None, ath=None, iat=None, typ="dpop+jwt"):
    claims = {
        "jti": util.random_token(16),
        "htm": htm,
        "htu": htu,
        "iat": iat or int(time.time()),
    }
    if nonce:
        claims["nonce"] = nonce
    if ath:
        claims["ath"] = ath
    # header must carry the public JWK; grindvakt's jwt.sign sets alg/kid, so
    # build the header by hand via a raw sign using jose through jwt.sign then
    # patch: simpler to sign with a key whose kid is None and add jwk by re-encoding.
    return _sign_with_jwk_header(key, claims, typ)


def _sign_with_jwk_header(key, claims, typ):
    """Produce a DPoP JWT: header {typ, alg, jwk}, ES256 over the payload."""
    import json

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    priv, pub_jwk = key
    header = {"typ": typ, "alg": "ES256", "jwk": pub_jwk}
    signing_input = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(claims).encode())}"
    der = priv.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{signing_input}.{b64(sig)}"


@pytest.fixture(scope="module")
def dpop_key():
    """(private key object, public JWK dict) for an ES256 DPoP key."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import ec

    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()

    def b64(i):
        return base64.urlsafe_b64encode(i.to_bytes(32, "big")).rstrip(b"=").decode()

    return priv, {"kty": "EC", "crv": "P-256", "x": b64(nums.x), "y": b64(nums.y)}


def test_config_validation():
    with pytest.raises(ValueError):
        dpop.DpopConfig(require_nonce=True)
    c = dpop.DpopConfig(require_nonce=True, nonce_secret="s")
    assert c.require_nonce and c.proof_max_age_secs == 300
    n = dpop.issue_nonce(c)
    assert n and n != dpop.issue_nonce(dpop.DpopConfig(require_nonce=True, nonce_secret="other"))


def test_validate_and_replay(dpop_key):
    """A fresh proof validates once; presenting it again is a replay."""
    store = dpop.InMemoryReplayStore()
    cfg = dpop.DpopConfig()
    proof = make_proof(dpop_key, "POST", TOKEN_URL)
    p = dpop.validate_proof(store, cfg, proof, "POST", TOKEN_URL)
    assert p.jkt == keys.jwk_thumbprint(dpop_key[1])
    with pytest.raises(DpopReplayError):
        dpop.validate_proof(store, cfg, proof, "POST", TOKEN_URL)


def test_htm_htu_mismatch(dpop_key):
    store = dpop.InMemoryReplayStore()
    cfg = dpop.DpopConfig()
    with pytest.raises(DpopInvalidError):
        dpop.validate_proof(store, cfg, make_proof(dpop_key, "POST", TOKEN_URL), "GET", TOKEN_URL)
    with pytest.raises(DpopInvalidError):
        dpop.validate_proof(store, cfg, make_proof(dpop_key, "POST", TOKEN_URL), "POST", TOKEN_URL + "/")
    with pytest.raises(DpopInvalidError):
        dpop.validate_proof(
            store,
            cfg,
            make_proof(dpop_key, "POST", TOKEN_URL, typ="JWT"),
            "POST",
            TOKEN_URL,
        )
    with pytest.raises(DpopInvalidError):
        dpop.validate_proof(
            store,
            cfg,
            make_proof(dpop_key, "POST", TOKEN_URL, iat=int(time.time()) - 10_000),
            "POST",
            TOKEN_URL,
        )


def test_nonce_challenge_then_accept(dpop_key):
    """Without a nonce the server demands one; with the issued nonce it accepts."""
    store = dpop.InMemoryReplayStore()
    cfg = dpop.DpopConfig(require_nonce=True, nonce_secret="nonce-key")
    with pytest.raises(DpopNonceRequiredError):
        dpop.validate_proof(store, cfg, make_proof(dpop_key, "POST", TOKEN_URL), "POST", TOKEN_URL)
    nonce = dpop.issue_nonce(cfg)
    dpop.validate_proof(
        store,
        cfg,
        make_proof(dpop_key, "POST", TOKEN_URL, nonce=nonce),
        "POST",
        TOKEN_URL,
    )
    # A forged / stale nonce is re-challenged (RFC 9449 section 8), not merely rejected.
    with pytest.raises(DpopNonceRequiredError):
        dpop.validate_proof(
            store,
            cfg,
            make_proof(dpop_key, "POST", TOKEN_URL, nonce="forged"),
            "POST",
            TOKEN_URL,
        )


def test_no_replay_store_fails_closed():
    with pytest.raises(ValueError, match="no longer supported"):
        dpop.NoReplayStore()


def test_python_replay_store_and_failure(dpop_key, unraisable):
    """A Python replay store is honoured; if it raises, validation fails closed
    with DpopServerError (not silently as a replay)."""
    seen = set()

    class Store:
        def record(self, jti, ttl):
            assert isinstance(ttl, int)
            if jti in seen:
                return False
            seen.add(jti)
            return True

    cfg = dpop.DpopConfig()
    proof = make_proof(dpop_key, "POST", TOKEN_URL)
    dpop.validate_proof(Store(), cfg, proof, "POST", TOKEN_URL)
    with pytest.raises(DpopReplayError):
        dpop.validate_proof(Store(), cfg, proof, "POST", TOKEN_URL)

    class Broken:
        def record(self, jti, ttl):
            raise RuntimeError("redis down")

    with pytest.raises(DpopServerError):
        dpop.validate_proof(Broken(), cfg, make_proof(dpop_key, "POST", TOKEN_URL), "POST", TOKEN_URL)
    unraisable.expect(RuntimeError, "redis down", count=1, adapter=Broken)

    with pytest.raises(TypeError, match="record"):
        dpop.validate_proof(object(), cfg, proof, "POST", TOKEN_URL)


def test_dpop_bound_token_end_to_end(op, dpop_key):
    """client_credentials with a DPoP proof yields a DPoP-bound token; userinfo
    rejects it as plain Bearer and accepts it with a matching resource proof."""
    store = dpop.InMemoryReplayStore()
    cfg = dpop.DpopConfig()
    proof = dpop.validate_proof(store, cfg, make_proof(dpop_key, "POST", TOKEN_URL), "POST", TOKEN_URL)
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
        dpop=proof,
    )
    assert tr.token_type == "DPoP"
    with pytest.raises(OAuthError):
        op.userinfo(tr.access_token)  # bound token presented without proof
    ath = base64.urlsafe_b64encode(hashlib.sha256(tr.access_token.encode()).digest()).rstrip(b"=").decode()
    rp = dpop.validate_resource_proof(
        store,
        cfg,
        make_proof(dpop_key, "GET", USERINFO_URL, ath=ath),
        "GET",
        USERINFO_URL,
        tr.access_token,
    )
    with pytest.raises(OAuthError, match="openid scope"):
        op.userinfo(tr.access_token, presented_jkt=rp.jkt)
    with pytest.raises(DpopInvalidError):  # wrong ath
        dpop.validate_resource_proof(
            store,
            cfg,
            make_proof(dpop_key, "GET", USERINFO_URL, ath="x"),
            "GET",
            USERINFO_URL,
            tr.access_token,
        )
    with pytest.raises(OAuthError):  # wrong key thumbprint
        op.userinfo(tr.access_token, presented_jkt="someone-else")


def test_dpop_proof_class():
    with pytest.raises(TypeError):
        dpop.DpopProof("abc")
    assert dpop.InMemoryReplayStore().record("j", 10) is True


def test_signed_userinfo_dpop_binding(op, dpop_key):
    """signed_userinfo enforces the DPoP binding like userinfo."""
    from conftest import REDIRECT_URI, basic_auth, code_from_redirect
    from pygrindvakt import pkce, request

    store = dpop.InMemoryReplayStore()
    cfg = dpop.DpopConfig()
    proof = dpop.validate_proof(store, cfg, make_proof(dpop_key, "POST", TOKEN_URL), "POST", TOKEN_URL)
    verifier = util.random_token(32)
    req = request.AuthorizationRequest.from_params(
        [
            ("client_id", "demo"),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
            ("nonce", "n"),
            ("code_challenge", pkce.s256_challenge(verifier)),
            ("code_challenge_method", "S256"),
        ]
    )
    op.validate_authorization_request(req)
    code = code_from_redirect(op.authorization_redirect(req, "alice"))
    tr = op.handle_token_request(
        [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", verifier),
        ],
        TOKEN_URL,
        auth_header=basic_auth("demo", "s3cret"),
        dpop=proof,
    )
    assert tr.token_type == "DPoP"
    for jkt in (None, "someone-else"):
        with pytest.raises(OAuthError) as ei:
            op.signed_userinfo(tr.access_token, presented_jkt=jkt)
        assert ei.value.code == "invalid_dpop_proof"
    assert op.signed_userinfo(tr.access_token, presented_jkt=proof.jkt).count(".") == 2
