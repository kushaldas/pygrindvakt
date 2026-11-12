"""Package-level checks: version, submodule registration, exception hierarchy."""

import ast
import pathlib

import pygrindvakt
import pytest
from pygrindvakt import BadRequestError, OAuthError

SUBMODULES = [
    "client",
    "discovery",
    "dpop",
    "federation",
    "http",
    "jwt",
    "keys",
    "mac",
    "metadata",
    "pkce",
    "provider",
    "request",
    "rp",
    "tokens",
    "util",
]


def test_version():
    """The version is pinned in Cargo.toml and pyproject.toml; keep them in sync."""
    assert pygrindvakt.__version__ == "0.5.0"


def test_submodules_importable():
    """Every grindvakt area is a real importable submodule (registered in sys.modules)."""
    import importlib

    for name in SUBMODULES:
        assert hasattr(pygrindvakt, name), name
        mod = importlib.import_module(f"pygrindvakt.{name}")
        assert mod is getattr(pygrindvakt, name)
        assert mod.__name__ == f"pygrindvakt.{name}"


def test_exception_hierarchy():
    """All errors derive from GrindvaktError; DPoP errors form their own subtree."""
    E = pygrindvakt
    for cls in (
        E.BadRequestError,
        E.AuthnError,
        E.StateError,
        E.ConfigError,
        E.CryptoError,
        E.AttributeMappingError,
        E.JoseError,
        E.UnknownKeyError,
        E.JsonError,
        E.InternalError,
        E.NoBoundEndpointError,
        E.UnknownModuleError,
        E.DpopError,
        OAuthError,
    ):
        assert issubclass(cls, E.GrindvaktError), cls
    for cls in (
        E.DpopInvalidError,
        E.DpopReplayError,
        E.DpopNonceRequiredError,
        E.DpopServerError,
    ):
        assert issubclass(cls, E.DpopError), cls
    assert issubclass(E.UnknownKeyError, E.JoseError)
    assert E.AuthnError.status_hint == 401
    assert E.UnknownKeyError.status_hint == 401
    assert E.NoBoundEndpointError.status_hint == 404
    assert E.BadRequestError.status_hint == 400
    assert E.GrindvaktError.status_hint == 500


def test_oauth_error_is_constructible_and_renders():
    """Applications raise OAuthError themselves; it carries data and renders both ways."""
    e = OAuthError("access_denied", "nope", state="xyz")
    assert (e.code, e.description, e.state) == ("access_denied", "nope", "xyz")
    assert e.http_status == 400 and e.status_hint == 400
    assert str(e) == "access_denied: nope"
    r = e.to_response()
    assert r.status == 400
    assert r.header("content-type") == "application/json"
    assert r.header("cache-control") == "no-store"
    assert b'"error":"access_denied"' in r.body and b'"state":"xyz"' in r.body
    rd = e.to_redirect("https://rp.example.com/cb?x=1", "query")
    assert rd.status == 302
    assert rd.header("location") == "https://rp.example.com/cb?x=1&error=access_denied&error_description=nope&state=xyz"
    fragment = e.to_redirect("https://rp.example.com/cb", "fragment")
    assert fragment.header("location") == (
        "https://rp.example.com/cb#error=access_denied&error_description=nope&state=xyz"
    )
    with pytest.raises(ValueError, match="response_mode"):
        e.to_redirect("https://rp.example.com/cb", "form_post")
    with pytest.raises(TypeError):
        e.to_redirect("https://rp.example.com/cb")


def test_oauth_error_invalid_client_gets_www_authenticate():
    """invalid_client is a 401 with a WWW-Authenticate challenge (RFC 6749 section 5.2)."""
    r = OAuthError("invalid_client").to_response()
    assert r.status == 401
    assert r.header("www-authenticate") == "Basic"
    assert OAuthError("server_error").http_status == 500
    assert OAuthError("temporarily_unavailable").http_status == 503


def test_oauth_error_rejects_unknown_code():
    """A typo in the code fails at raise time, not at render time."""
    import pytest

    with pytest.raises(ValueError):
        OAuthError("not_a_code")


def test_oauth_error_with_state_copies():
    e = OAuthError("invalid_request", "bad").with_state("s1")
    assert e.state == "s1" and e.description == "bad"


def test_py_typed_is_not_partial():
    """The package is fully typed: py.typed must not carry the ``partial`` marker."""
    import pathlib

    marker = pathlib.Path(pygrindvakt.__file__).parent / "py.typed"
    assert marker.exists()
    assert "partial" not in marker.read_text()


def test_errors_imports_after_native():
    """OAuthError must follow _native, which resolves it lazily; keep the order."""
    tree = ast.parse(pathlib.Path(pygrindvakt.__file__).read_text())
    mods = [n.module for n in tree.body if isinstance(n, ast.ImportFrom)]
    assert mods.index("_native") < mods.index("errors"), "OAuthError must follow _native"


_HOSTILE_REDIRECT_BASES = [
    "https://rp.example.com/cb\r\nX-Injected: 1\r\nLocation: https://evil.example",
    "https://rp.example.com/cb\tx",
    " https://rp.example.com/cb",
    "https://rp.example.com/cb ",
    "https://rp.example.com/cb\u200b",
    "https://rp.example.com/\u202ecb",
    "https://good.example@evil.example/cb",
    "https://user:pw@rp.example.com/cb",
    "https://rp.example.com/cb#f",
    "not a url",
    "notaurl",
]


@pytest.mark.parametrize("mode", ["query", "fragment"])
@pytest.mark.parametrize("base", _HOSTILE_REDIRECT_BASES)
def test_to_redirect_rejects_hostile_base(base, mode):
    """A hostile base fails closed and the message never echoes the input."""
    e = OAuthError("access_denied", "nope", state="xyz")
    with pytest.raises(BadRequestError) as ei:
        e.to_redirect(base, mode)
    msg = str(ei.value)
    assert base.strip() not in msg
    assert "evil" not in msg and "X-Injected" not in msg and "not a url" not in msg


@pytest.mark.parametrize("description", ["\ud800", "ab\udfffcd", "x" * 600 + "\ud800", "\ud800\u202e"])
def test_oauth_error_str_survives_lone_surrogate(description):
    """str() and logging must not raise for a description decoded from JSON "\\ud800"."""
    e = OAuthError("invalid_request", description)
    text = str(e)
    assert text.startswith("invalid_request: ")
    assert not any(0xD800 <= ord(c) <= 0xDFFF for c in text)
    text.encode("utf-8")  # renderable
    assert e.description == description  # raw value preserved
    assert "invalid_request" in f"{e}" and repr(e)


@pytest.mark.parametrize("mode", ["query", "fragment"])
@pytest.mark.parametrize(
    "base",
    [
        "SECRET-PREFIX-" + "a" * 300,
        "https://SECRET-PREFIX-" + "a" * 300 + " b",
        "https://rp.example.com/" + "a" * 300 + "#SECRET-PREFIX",
        "https://SECRET-PREFIX:pw@rp.example.com/" + "a" * 300,
    ],
)
def test_to_redirect_long_malformed_base_is_not_echoed(base, mode):
    """A malformed base over 256 chars: no prefix of it reaches the message."""
    e = OAuthError("access_denied", "nope", state="xyz")
    with pytest.raises(BadRequestError) as ei:
        e.to_redirect(base, mode)
    assert "SECRET-PREFIX" not in str(ei.value)
    assert str(ei.value) == "redirect_uri must be an absolute URI without a fragment (not echoed)"


@pytest.mark.parametrize(
    ("base", "mode", "expected"),
    [
        (
            "https://rp.example.com/cb",
            "query",
            "https://rp.example.com/cb?error=access_denied&error_description=nope&state=xyz",
        ),
        (
            "https://rp.example.com/cb?x=1",
            "query",
            "https://rp.example.com/cb?x=1&error=access_denied&error_description=nope&state=xyz",
        ),
        (
            "com.example.app:/cb",
            "query",
            "com.example.app:/cb?error=access_denied&error_description=nope&state=xyz",
        ),
        (
            "http://127.0.0.1:8080/cb",
            "fragment",
            "http://127.0.0.1:8080/cb#error=access_denied&error_description=nope&state=xyz",
        ),
        (
            "https://rp.example.com/cb",
            "fragment",
            "https://rp.example.com/cb#error=access_denied&error_description=nope&state=xyz",
        ),
    ],
)
def test_to_redirect_valid_bases_unchanged(base, mode, expected):
    e = OAuthError("access_denied", "nope", state="xyz")
    rd = e.to_redirect(base, mode)
    assert rd.status == 302
    assert rd.header("location") == expected
