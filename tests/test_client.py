"""Client registration objects and the in-memory client store."""

import pytest
from pygrindvakt import client


def test_client_defaults():
    """Defaults mirror grindvakt: code, authorization_code, client_secret_basic, public."""
    c = client.Client("id")
    assert c.response_types == ["code"]
    assert c.grant_types == ["authorization_code"]
    assert c.token_endpoint_auth_method == client.AUTH_CLIENT_SECRET_BASIC
    assert c.subject_type == "public"
    assert c.client_secret is None and c.jwks is None and c.scope is None
    assert c.allows_response_type("code") and not c.allows_response_type("token")
    assert "Client(" in repr(c) and "secret" not in repr(c).lower().replace("client_secret", "")


def test_client_rejects_unknown_keyword():
    """A typo like redirect_uri= must fail loudly instead of yielding an unusable client."""
    with pytest.raises(TypeError):
        client.Client("id", redirect_uri="https://x")


def test_client_is_keyword_only_after_id():
    with pytest.raises(TypeError):
        client.Client("id", "secret")


def test_client_dict_round_trip():
    c = client.Client(
        "id",
        client_secret="s",
        redirect_uris=["https://x/cb"],
        scope="a b",
        client_name="N",
    )
    d = c.to_dict()
    assert d["client_id"] == "id" and d["redirect_uris"] == ["https://x/cb"] and d["scope"] == "a b"
    c2 = client.Client.from_dict(d)
    assert c2.client_name == "N" and c2.allows_redirect("https://x/cb")


def test_registration_fingerprint():
    def mk(**kw):
        base = {"client_secret": "s", "redirect_uris": ["https://x/cb"], "client_name": "N"}
        base.update(kw)
        return client.Client("id", **base)

    c = mk()
    fp = c.registration_fingerprint()
    assert isinstance(fp, str) and fp
    assert fp == c.registration_fingerprint() == mk().registration_fingerprint()
    assert client.Client.from_dict(c.to_dict()).registration_fingerprint() == fp
    assert mk(redirect_uris=["https://x/other"]).registration_fingerprint() != fp
    assert mk(client_secret="t").registration_fingerprint() != fp
    assert mk(client_name="M").registration_fingerprint() != fp


def test_from_dict_rejects_unknown_keys():
    with pytest.raises(ValueError, match="redirect_uri"):
        client.Client.from_dict({"client_id": "x", "redirect_uri": "https://x"})


def test_from_dict_applies_defaults():
    c = client.Client.from_dict({"client_id": "x"})
    assert c.grant_types == ["authorization_code"]


def test_client_jwks():
    from pygrindvakt import keys

    k = keys.signing_key_from_jwk(keys.generate_ec_jwk(), kid="rp")
    c = client.Client(
        "x",
        token_endpoint_auth_method=client.AUTH_PRIVATE_KEY_JWT,
        jwks=k.to_public_jwks(),
    )
    assert c.jwks["keys"][0]["kid"] == "rp"


def test_store_seed_get_put():
    s = client.InMemoryClientStore([client.Client("a"), client.Client("b")])
    assert s.get("a").client_id == "a"
    assert s.get("zzz") is None
    s.put(client.Client("c", client_name="C"))
    assert s.get("c").client_name == "C"
    s.put({"client_id": "d"})  # dicts accepted too
    assert s.get("d").client_id == "d"


def test_store_rejects_duplicate_ids():
    """grindvakt silently keeps the last duplicate; the binding refuses instead."""
    with pytest.raises(ValueError, match="duplicate"):
        client.InMemoryClientStore([client.Client("a"), client.Client("a")])


def test_store_ttl_expiry():
    """put_with_ttl entries disappear once expired (TTL 0 expires immediately)."""
    s = client.InMemoryClientStore()
    s.put_with_ttl(client.Client("t"), 3600)
    assert s.get("t") is not None
    s.put_with_ttl(client.Client("u"), 0)
    assert s.get("u") is None


def test_auth_constants():
    assert client.AUTH_NONE == "none"
    assert client.AUTH_CLIENT_SECRET_POST == "client_secret_post"
    assert client.AUTH_PRIVATE_KEY_JWT == "private_key_jwt"
