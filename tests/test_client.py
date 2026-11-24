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


POLICY = {
    "sector_identifier_uri": "https://rp.example.com/sector.json",
    "request_object_signing_alg": "ES256",
    "token_endpoint_auth_signing_alg": "ES256",
    "id_token_encrypted_response_alg": "ECDH-ES",
    "id_token_encrypted_response_enc": "A256GCM",
    "userinfo_encrypted_response_alg": "RSA-OAEP-256",
    "userinfo_encrypted_response_enc": "A128CBC-HS256",
}

# Every Client field set. Update when core grows a field: the self-check test
# below fails until the binding accepts it.
FULL_CLIENT = {
    "client_id": "full",
    "client_secret": "s",
    "redirect_uris": ["https://x/cb"],
    "response_types": ["code"],
    "grant_types": ["authorization_code", "refresh_token"],
    "token_endpoint_auth_method": "private_key_jwt",
    "jwks": {"keys": []},
    "scope": "a b",
    "subject_type": "pairwise",
    "client_name": "N",
    "response_policy": POLICY,
}


def test_response_policy_default_and_fresh_dict():
    c = client.Client("id")
    assert c.response_policy == {}
    assert "response_policy" not in c.to_dict()
    c = client.Client("id", response_policy={"token_endpoint_auth_signing_alg": "ES256"})
    got = c.response_policy
    assert got == {"token_endpoint_auth_signing_alg": "ES256"}
    got["id_token_encrypted_response_alg"] = "x"  # mutating the copy changes nothing
    assert c.response_policy == {"token_endpoint_auth_signing_alg": "ES256"}
    assert client.Client("id", response_policy=None).response_policy == {}


def test_response_policy_round_trip_and_store():
    c = client.Client("id", response_policy=POLICY)
    assert c.response_policy == POLICY
    assert c.to_dict()["response_policy"] == POLICY
    assert client.Client.from_dict({"client_id": "id", "response_policy": POLICY}).response_policy == POLICY
    store = client.InMemoryClientStore()
    store.put(c)
    assert store.get("id").response_policy == POLICY
    store.put({"client_id": "d", "response_policy": POLICY})
    assert store.get("d").response_policy == POLICY
    assert client.InMemoryClientStore([c.to_dict()]).get("id").response_policy == POLICY


def test_response_policy_contributes_to_fingerprint():
    fp = client.Client("id").registration_fingerprint()
    pinned = client.Client("id", response_policy={"token_endpoint_auth_signing_alg": "ES256"})
    assert pinned.registration_fingerprint() != fp
    other = client.Client("id", response_policy={"token_endpoint_auth_signing_alg": "RS256"})
    assert other.registration_fingerprint() != pinned.registration_fingerprint()
    assert client.Client.from_dict(pinned.to_dict()).registration_fingerprint() == pinned.registration_fingerprint()


@pytest.mark.parametrize("bad", [{"nope": "x"}, {"scope": "x"}])
def test_response_policy_rejects_unknown_keys(bad):
    with pytest.raises(ValueError, match="unknown response_policy"):
        client.Client("id", response_policy=bad)
    with pytest.raises(ValueError, match="unknown response_policy"):
        client.Client.from_dict({"client_id": "id", "response_policy": bad})


@pytest.mark.parametrize("value", [1, None, ["ES256"], True])
def test_response_policy_rejects_non_string_values(value):
    bad = {"token_endpoint_auth_signing_alg": value}
    with pytest.raises(ValueError, match="must be a string"):
        client.Client("id", response_policy=bad)
    with pytest.raises(ValueError, match="must be a string"):
        client.Client.from_dict({"client_id": "id", "response_policy": bad})


def test_response_policy_rejects_empty_strings():
    bad = {"token_endpoint_auth_signing_alg": ""}
    with pytest.raises(ValueError, match="must not be empty"):
        client.Client("id", response_policy=bad)
    with pytest.raises(ValueError, match="must not be empty"):
        client.Client.from_dict({"client_id": "id", "response_policy": bad})


def test_from_dict_null_response_policy_means_unset():
    c = client.Client.from_dict({"client_id": "id", "response_policy": None})
    assert c.response_policy == {}
    assert "response_policy" not in c.to_dict()
    assert c.registration_fingerprint() == client.Client("id").registration_fingerprint()


def test_response_policy_rejects_non_dict():
    with pytest.raises(ValueError):
        client.Client("id", response_policy=["x"])
    with pytest.raises(ValueError):
        client.Client.from_dict({"client_id": "id", "response_policy": "x"})


def test_to_dict_keys_are_all_accepted_by_from_dict():
    """Self-checking allow-list: a fully populated client round-trips, so
    ``to_dict()`` can never emit a key ``from_dict()`` rejects. The Rust unit
    test ``client_fields_match_core_serialization`` compares the allow-list
    with core's own serialization of ``grindvakt::client::Client``."""
    c = client.Client.from_dict(FULL_CLIENT)
    d = c.to_dict()
    assert set(d) == set(FULL_CLIENT)
    assert d["response_policy"] == POLICY
    assert client.Client.from_dict(d).to_dict() == d
