"""TokenCodec: sealed authorization codes / access / refresh tokens."""

import time

import pytest
from pygrindvakt import GrindvaktError, tokens


def _code(exp=None):
    return tokens.AuthCodePayload(
        client_id="demo",
        redirect_uri="https://rp/cb",
        scope="openid",
        sub="alice",
        auth_time=int(time.time()),
        exp=exp or int(time.time()) + 60,
        nonce="n",
        claims={"email": "a@b", "groups": ["x", "y"]},
        registration_digest="dig",
    )


def test_code_round_trip():
    """A sealed code opens to an equal payload, including nested JSON claims."""
    codec = tokens.TokenCodec("secret")
    sealed = codec.seal_code(_code())
    assert sealed.count(".") == 4  # compact JWE
    opened = codec.open_code(sealed)
    assert opened.sub == "alice" and opened.nonce == "n"
    assert opened.claims == {"email": "a@b", "groups": ["x", "y"]}
    assert opened.to_dict()["client_id"] == "demo"
    assert "AuthCodePayload" in repr(opened)


def test_expired_code_rejected():
    codec = tokens.TokenCodec("secret")
    sealed = codec.seal_code(_code(exp=int(time.time()) - 1))
    with pytest.raises(GrindvaktError):
        codec.open_code(sealed)


def test_wrong_secret_rejected():
    sealed = tokens.TokenCodec("a").seal_code(_code())
    with pytest.raises(GrindvaktError):
        tokens.TokenCodec("b").open_code(sealed)


def test_type_confusion_rejected():
    """A code cannot be presented as an access token or refresh token."""
    codec = tokens.TokenCodec("secret")
    sealed = codec.seal_code(_code())
    with pytest.raises(GrindvaktError):
        codec.open_access_token(sealed)
    with pytest.raises(GrindvaktError):
        codec.open_refresh_token(sealed)


def test_key_rotation_with_previous_secrets():
    """Tokens sealed under an old secret still open after rotation."""
    old = tokens.TokenCodec("old")
    at = tokens.AccessTokenPayload(client_id="demo", sub="alice", scope="openid", exp=int(time.time()) + 60)
    sealed = old.seal_access_token(at)
    new = tokens.TokenCodec("new", previous_secrets=["old"])
    assert new.open_access_token(sealed).sub == "alice"
    with pytest.raises(GrindvaktError):
        tokens.TokenCodec("new").open_access_token(sealed)


def test_refresh_payload_round_trip_and_dpop_binding():
    codec = tokens.TokenCodec("s")
    rt = tokens.RefreshTokenPayload(
        client_id="demo",
        sub="a",
        scope="openid",
        auth_time=1,
        exp=int(time.time()) + 5,
        cnf_jkt="thumb",
    )
    opened = codec.open_refresh_token(codec.seal_refresh_token(rt))
    assert opened.cnf_jkt == "thumb" and opened.acr is None


def test_payload_from_dict():
    p = tokens.AccessTokenPayload.from_dict({"client_id": "c", "sub": "s", "scope": "x", "exp": 5})
    assert p.claims == {} and p.exp == 5
    with pytest.raises(ValueError):
        tokens.AccessTokenPayload.from_dict({"sub": "s"})


def test_codec_repr_never_renders_the_secret():
    r = repr(tokens.TokenCodec("hunter2-super-secret"))
    assert "hunter2" not in r and "<secret>" in r


def _refresh(**kw):
    return tokens.RefreshTokenPayload(
        client_id="demo",
        sub="alice",
        scope="openid",
        auth_time=1,
        exp=int(time.time()) + 60,
        **kw,
    )


def _code_kw(**kw):
    kw.setdefault("registration_digest", "dig")
    return tokens.AuthCodePayload(
        client_id="demo",
        redirect_uri="https://rp/cb",
        scope="openid",
        sub="alice",
        auth_time=1,
        exp=int(time.time()) + 60,
        claims={"email": "a@b"},
        **kw,
    )


def test_new_payload_fields_round_trip():
    codec = tokens.TokenCodec("secret")
    code = _code_kw(registration_digest="dig-1", userinfo_claims={"email": "u@b", "n": 1})
    opened = codec.open_code(codec.seal_code(code))
    assert opened.registration_digest == "dig-1"
    assert opened.userinfo_claims == {"email": "u@b", "n": 1}
    again = tokens.AuthCodePayload.from_dict(opened.to_dict())
    assert again.registration_digest == "dig-1" and again.userinfo_claims == {"email": "u@b", "n": 1}

    rt = _refresh(userinfo_claims={"email": "u@b"})
    ropened = codec.open_refresh_token(codec.seal_refresh_token(rt))
    assert ropened.userinfo_claims == {"email": "u@b"}
    assert tokens.RefreshTokenPayload.from_dict(ropened.to_dict()).userinfo_claims == {"email": "u@b"}


def test_userinfo_claims_none_vs_empty():
    codec = tokens.TokenCodec("secret")
    for make, seal, opn in (
        (_code_kw, codec.seal_code, codec.open_code),
        (_refresh, codec.seal_refresh_token, codec.open_refresh_token),
    ):
        assert make().userinfo_claims is None
        assert make(userinfo_claims=None).userinfo_claims is None
        assert make(userinfo_claims={}).userinfo_claims == {}
        assert opn(seal(make())).userinfo_claims is None
        assert opn(seal(make(userinfo_claims={}))).userinfo_claims == {}
        assert make().claims == make(userinfo_claims={}).claims


def test_pre_0_6_dict_shape_loads():
    code = tokens.AuthCodePayload.from_dict(
        {
            "client_id": "c",
            "redirect_uri": "https://rp/cb",
            "scope": "openid",
            "sub": "s",
            "auth_time": 1,
            "exp": 2,
            "claims": {"email": "a@b"},
        }
    )
    assert code.registration_digest is None and code.userinfo_claims is None
    d = code.to_dict()
    assert "registration_digest" not in d and "userinfo_claims" not in d
    rt = tokens.RefreshTokenPayload.from_dict(
        {"client_id": "c", "sub": "s", "scope": "openid", "auth_time": 1, "exp": 2}
    )
    assert rt.userinfo_claims is None
    assert "userinfo_claims" not in rt.to_dict()


def test_registration_digest_not_in_repr():
    assert "secret-digest" not in repr(_code_kw(registration_digest="secret-digest"))


def test_bad_userinfo_claims_type_raises():
    with pytest.raises((TypeError, ValueError)):
        _code_kw(userinfo_claims="nope")
    with pytest.raises((TypeError, ValueError)):
        _refresh(userinfo_claims=[1, 2])


def _no_digest():
    return {
        "client_id": "demo",
        "redirect_uri": "https://rp/cb",
        "scope": "openid",
        "sub": "alice",
        "auth_time": 1,
        "exp": int(time.time()) + 60,
    }


def test_auth_code_without_digest_warns_deprecation():
    with pytest.warns(DeprecationWarning, match="registration_fingerprint") as rec:
        tokens.AuthCodePayload(**_no_digest())
    assert len(rec) == 1
    assert rec[0].filename == __file__
    assert "authorization_redirect_with_authorized_claims" in str(rec[0].message)
    with pytest.warns(DeprecationWarning):
        tokens.AuthCodePayload(**_no_digest(), registration_digest=None)


def test_auth_code_with_digest_does_not_warn(recwarn):
    tokens.AuthCodePayload(**_no_digest(), registration_digest="dig")
    assert not [w for w in recwarn if issubclass(w.category, DeprecationWarning)]


def test_opening_digestless_code_does_not_warn(recwarn):
    """Old (0.5.x-style) sealed codes carry no digest; decoding them is silent."""
    codec = tokens.TokenCodec("secret")
    with pytest.warns(DeprecationWarning):
        legacy = tokens.AuthCodePayload(**_no_digest())
    sealed = codec.seal_code(legacy)
    recwarn.clear()
    opened = codec.open_code(sealed)
    tokens.AuthCodePayload.from_dict(opened.to_dict())
    assert opened.registration_digest is None
    assert not [w for w in recwarn if issubclass(w.category, DeprecationWarning)]


def test_refresh_token_payload_has_no_digest_and_does_not_warn(recwarn):
    _refresh()
    assert not [w for w in recwarn if issubclass(w.category, DeprecationWarning)]
