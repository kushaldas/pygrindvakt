"""Tests for ``pygrindvakt.federation``.

The network is mocked with ``FakeHttpClient`` (an object implementing the
``HttpClient`` protocol: ``get`` / ``post_form`` returning
``(status, body, content_type)``). The federation topology is a leaf RP whose
authority is a single trust anchor (TA). What ``resolve_via_trust_anchors``
actually fetches upstream:

1. ``<TA>/.well-known/openid-federation`` - the TA's self-signed entity
   configuration, which must advertise ``federation_resolve_endpoint``.
2. ``<resolve_endpoint>?sub=<leaf>&trust_anchor=<TA>`` - a resolve response
   (``typ = resolve-response+jwt``) signed by the TA, carrying the resolved
   ``metadata`` and a ``trust_chain`` of ``[leaf EC, TA->leaf subordinate
   statement, TA EC]``.

The leaf's own ``.well-known`` and the TA's ``federation_fetch_endpoint`` are
never contacted by the resolver.
"""

import base64
import json
import time
import warnings
from urllib.parse import parse_qs, quote, urlsplit

import pygrindvakt
import pytest
from pygrindvakt import federation, jwt, keys

LEAF = "https://rp.example.org"
TA = "https://ta.example.org"
RESOLVE_EP = TA + "/resolve"
WELL_KNOWN = "/.well-known/openid-federation"

LEAF_METADATA = {
    "openid_relying_party": {
        "redirect_uris": [LEAF + "/callback"],
        "client_name": "RP",
    }
}


def make_key(kid: str):
    return keys.signing_key_from_jwk(keys.generate_ec_jwk(), alg="ES256", kid=kid)


def now() -> int:
    return int(time.time())


def subordinate_statement(signer, iss: str, sub: str, subject_jwks: dict) -> str:
    """A ``iss``-issued statement about ``sub`` carrying ``sub``'s federation keys."""
    claims = {
        "iss": iss,
        "sub": sub,
        "iat": now(),
        "exp": now() + 3600,
        "jwks": subject_jwks,
    }
    return jwt.sign(signer, claims, typ=federation.ENTITY_STATEMENT_TYP)


def resolve_response(
    signer,
    iss: str,
    sub: str,
    metadata: dict,
    chain: list[str],
    trust_marks=None,
    exp: int | None = None,
) -> str:
    claims = {
        "iss": iss,
        "sub": sub,
        "iat": now(),
        "exp": now() + 3600 if exp is None else exp,
        "metadata": metadata,
        "trust_chain": chain,
    }
    if trust_marks is not None:
        claims["trust_marks"] = trust_marks
    return jwt.sign(signer, claims, typ=federation.RESOLVE_RESPONSE_TYP)


def signed_jwks_document(signer, subject: str, keys_list: list[dict]) -> str:
    claims = {
        "iss": subject,
        "sub": subject,
        "iat": now(),
        "exp": now() + 3600,
        "keys": keys_list,
    }
    return jwt.sign(signer, claims, typ=federation.JWK_SET_TYP)


class FakeHttpClient:
    """URL -> (status, body, content_type) table implementing the HttpClient protocol.

    A URL with a query string falls back to its query-less form so the resolve
    and collection endpoints (which get ``?sub=...`` / ``?entity_type=...``
    appended) can be registered by their base URL. Every request is recorded in
    ``calls`` for assertions.
    """

    def __init__(self, routes: dict[str, tuple[int, bytes | str, str | None]]):
        self.routes = routes
        self.calls: list[str] = []

    def get(self, url: str):
        self.calls.append(url)
        hit = self.routes.get(url)
        if hit is None:
            hit = self.routes.get(url.split("?", 1)[0])
        if hit is None:
            return (404, b"", None)
        status, body, content_type = hit
        if isinstance(body, str):
            body = body.encode()
        return (status, body, content_type)

    def post_form(self, url: str, form, headers):
        self.calls.append("POST " + url)
        return (404, b"", None)


class Federation:
    """A leaf + trust anchor with all the signed artefacts the resolver needs."""

    def __init__(self):
        self.ta_key = make_key("ta-1")
        self.leaf_key = make_key("rp-1")
        self.leaf_ec = federation.build_entity_configuration(
            self.leaf_key,
            LEAF,
            self.leaf_key.to_public_jwks(),
            [TA],
            LEAF_METADATA,
            None,
            3600,
        )
        self.ta_ec = federation.build_entity_configuration(
            self.ta_key,
            TA,
            self.ta_key.to_public_jwks(),
            [],
            {
                "federation_entity": {
                    "federation_resolve_endpoint": RESOLVE_EP,
                    "federation_fetch_endpoint": TA + "/fetch",
                }
            },
            None,
            3600,
        )
        self.subordinate = subordinate_statement(self.ta_key, TA, LEAF, self.leaf_key.to_public_jwks())

    def trust_anchors(self) -> dict:
        return {TA: self.ta_key.to_public_jwks()}

    def chain(self) -> list[str]:
        return [self.leaf_ec, self.subordinate, self.ta_ec]

    def network(
        self,
        chain: list[str] | None = None,
        resolve_signer=None,
        trust_marks=None,
        resolve_exp: int | None = None,
    ) -> FakeHttpClient:
        signer = resolve_signer or self.ta_key
        if chain is None:
            chain = self.chain()
        resolved = resolve_response(signer, TA, LEAF, LEAF_METADATA, chain, trust_marks, resolve_exp)
        return FakeHttpClient(
            {
                TA + WELL_KNOWN: (200, self.ta_ec, "application/entity-statement+jwt"),
                LEAF + WELL_KNOWN: (
                    200,
                    self.leaf_ec,
                    "application/entity-statement+jwt",
                ),
                RESOLVE_EP: (200, resolved, "application/resolve-response+jwt"),
            }
        )


@pytest.fixture
def fed() -> Federation:
    return Federation()


# ---------------------------------------------------------------------------
# Constants and module shape
# ---------------------------------------------------------------------------


def test_constants_match_upstream():
    """The three JWT ``typ`` constants are exposed with their spec values."""
    assert federation.ENTITY_STATEMENT_TYP == "entity-statement+jwt"
    assert federation.RESOLVE_RESPONSE_TYP == "resolve-response+jwt"
    assert federation.JWK_SET_TYP == "jwk-set+jwt"
    assert pygrindvakt.federation is federation


# ---------------------------------------------------------------------------
# Entity configurations: build / decode / verify
# ---------------------------------------------------------------------------


def test_build_entity_configuration_is_self_signed(fed):
    """A built entity configuration verifies against its own embedded jwks."""
    header = jwt.peek_header(fed.leaf_ec)
    assert header["typ"] == federation.ENTITY_STATEMENT_TYP
    assert header["alg"] == "ES256"
    assert header["kid"] == "rp-1"

    stmt = federation.verify_self_signed(fed.leaf_ec)
    assert isinstance(stmt, federation.EntityStatement)
    assert stmt.iss() == LEAF
    assert stmt.sub() == LEAF
    assert stmt.authority_hints() == [TA]
    assert stmt.metadata("openid_relying_party") == LEAF_METADATA["openid_relying_party"]
    assert stmt.metadata("openid_provider") is None
    assert stmt.jwks() == fed.leaf_key.to_public_jwks()
    claims = stmt.claims
    assert claims["iss"] == LEAF and claims["sub"] == LEAF
    assert claims["exp"] - claims["iat"] == 3600
    assert "trust_marks" not in claims
    assert repr(stmt) == f'EntityStatement(iss=Some("{LEAF}"), sub=Some("{LEAF}"))'


def test_build_entity_configuration_defaults_and_trust_marks(fed):
    """``trust_marks`` and ``lifetime`` are optional; trust marks are embedded verbatim."""
    marks = [{"id": "https://ta.example.org/marks/verified", "trust_mark": "x.y.z"}]
    token = federation.build_entity_configuration(
        fed.leaf_key, LEAF, fed.leaf_key.to_public_jwks(), [], {}, trust_marks=marks
    )
    stmt = federation.verify_self_signed(token)
    assert stmt.claims["trust_marks"] == marks
    assert stmt.claims["exp"] - stmt.claims["iat"] == 3600
    assert stmt.authority_hints() == []
    assert "authority_hints" not in stmt.claims


def test_build_entity_configuration_rejects_bad_jwks(fed):
    """``public_jwks`` must be a ``{"keys": [...]}`` dict."""
    with pytest.raises(Exception):  # noqa: B017 - core raises a bare Exception here
        federation.build_entity_configuration(fed.leaf_key, LEAF, {"nope": 1}, [], {}, None, 3600)


def test_decode_unverified_reads_claims_without_a_key(fed):
    """``decode_unverified`` exposes the claims of any statement without checking the signature."""
    stmt = federation.decode_unverified(fed.subordinate)
    assert stmt.iss() == TA
    assert stmt.sub() == LEAF
    assert stmt.jwks() == fed.leaf_key.to_public_jwks()
    assert stmt.metadata("openid_relying_party") is None

    # Tampered payloads still decode: signature is not checked.
    head, _, sig = fed.leaf_ec.split(".")
    import base64

    forged = (
        base64.urlsafe_b64encode(json.dumps({"iss": "https://evil.example", "sub": "https://evil.example"}).encode())
        .rstrip(b"=")
        .decode()
    )
    assert federation.decode_unverified(f"{head}.{forged}.{sig}").iss() == "https://evil.example"
    with pytest.raises(pygrindvakt.GrindvaktError):
        federation.verify_self_signed(f"{head}.{forged}.{sig}")


def test_decode_unverified_rejects_garbage():
    """A non-JWS string raises a GrindvaktError."""
    with pytest.raises(pygrindvakt.GrindvaktError):
        federation.decode_unverified("not a jwt")


def test_verify_against_explicit_jwks(fed):
    """``verify`` accepts the issuer's JWKS and rejects a different key."""
    stmt = federation.verify(fed.subordinate, fed.ta_key.to_public_jwks())
    assert stmt.iss() == TA and stmt.sub() == LEAF

    other = make_key("other")
    with pytest.raises(pygrindvakt.GrindvaktError):
        federation.verify(fed.subordinate, other.to_public_jwks())


def test_verify_typed_requires_matching_typ(fed):
    """``verify_typed`` enforces the ``typ`` header; the wrong typ fails."""
    ok = federation.verify_typed(fed.leaf_ec, fed.leaf_key.to_public_jwks(), federation.ENTITY_STATEMENT_TYP)
    assert ok.sub() == LEAF
    with pytest.raises(pygrindvakt.GrindvaktError):
        federation.verify_typed(fed.leaf_ec, fed.leaf_key.to_public_jwks(), federation.RESOLVE_RESPONSE_TYP)
    # ``verify`` is ``verify_typed`` with the entity-statement typ, so a resolve
    # response is refused by it.
    resolved = resolve_response(fed.ta_key, TA, LEAF, {}, fed.chain())
    with pytest.raises(pygrindvakt.GrindvaktError):
        federation.verify(resolved, fed.ta_key.to_public_jwks())
    assert federation.verify_typed(resolved, fed.ta_key.to_public_jwks(), federation.RESOLVE_RESPONSE_TYP).iss() == TA


def test_verify_self_signed_rejects_non_self_issued(fed):
    """A subordinate statement (iss != sub) is not an entity configuration."""
    with pytest.raises(pygrindvakt.AuthnError, match="not self-issued"):
        federation.verify_self_signed(fed.subordinate)


def test_statement_without_exp_is_rejected(fed):
    """Regression: entity statements must carry ``exp`` (OpenID Federation 1.0 section 3.1)."""
    claims = {
        "iss": LEAF,
        "sub": LEAF,
        "iat": now(),
        "jwks": fed.leaf_key.to_public_jwks(),
    }
    token = jwt.sign(fed.leaf_key, claims, typ=federation.ENTITY_STATEMENT_TYP)
    with pytest.raises(pygrindvakt.GrindvaktError):
        federation.verify(token, fed.leaf_key.to_public_jwks())
    with pytest.raises(pygrindvakt.GrindvaktError):
        federation.verify_self_signed(token)


def test_entity_statement_without_jwks_raises_on_jwks(fed):
    """``EntityStatement.jwks()`` raises BadRequestError when the claim is missing."""
    token = jwt.sign(
        fed.leaf_key,
        {"iss": LEAF, "sub": LEAF, "iat": now(), "exp": now() + 60},
        typ=federation.ENTITY_STATEMENT_TYP,
    )
    stmt = federation.decode_unverified(token)
    with pytest.raises(pygrindvakt.BadRequestError):
        stmt.jwks()
    with pytest.raises(pygrindvakt.GrindvaktError):
        federation.verify_self_signed(token)


def test_entity_statement_round_trips_as_argument(fed):
    """A returned EntityStatement is a frozen value object that can be re-extracted."""
    stmt = federation.verify_self_signed(fed.leaf_ec)
    with pytest.raises(AttributeError):
        stmt.claims = {}
    # ``claims`` is a fresh dict each time (no aliasing of Rust state).
    a = stmt.claims
    a["iss"] = "mutated"
    assert stmt.claims["iss"] == LEAF


# ---------------------------------------------------------------------------
# fetch_entity_configuration
# ---------------------------------------------------------------------------


def test_fetch_entity_configuration_uses_well_known(fed):
    """The configuration is fetched from ``<entity_id>/.well-known/openid-federation``."""
    http = fed.network()
    token = federation.fetch_entity_configuration(http, LEAF)
    assert token == fed.leaf_ec
    assert http.calls == [LEAF + WELL_KNOWN]
    # A trailing slash on the entity id does not double the separator.
    http = fed.network()
    federation.fetch_entity_configuration(http, LEAF + "/")
    assert http.calls == [LEAF + WELL_KNOWN]


def test_fetch_entity_configuration_non_200_is_internal_error(fed):
    """A non-200 answer raises InternalError naming the status."""
    http = FakeHttpClient({})
    with pytest.raises(pygrindvakt.InternalError, match="404"):
        federation.fetch_entity_configuration(http, LEAF)


def test_http_argument_must_implement_the_protocol():
    """Objects without ``get``/``post_form`` are rejected up front with TypeError."""
    with pytest.raises(TypeError, match="HttpClient"):
        federation.fetch_entity_configuration(object(), LEAF)


def test_http_client_exception_fails_closed(fed, unraisable):
    """An exception inside the Python client surfaces as InternalError, not a crash.

    The adapter also routes the traceback through ``sys.unraisablehook`` so
    operators can see it; the ``unraisable`` fixture records and checks it.
    """

    class Boom:
        def get(self, url):
            raise RuntimeError("network down")

        def post_form(self, url, form, headers):
            raise RuntimeError("network down")

    with pytest.raises(pygrindvakt.InternalError, match="network down"):
        federation.fetch_entity_configuration(Boom(), LEAF)
    unraisable.expect(RuntimeError, "network down", count=1, adapter=Boom)


# ---------------------------------------------------------------------------
# resolve_via_trust_anchors
# ---------------------------------------------------------------------------


def test_resolved_entity_exposes_trust_marks(fed):
    """Raw trust_marks from the signed resolve response are exposed, as a fresh copy per read."""
    marks = [{"trust_mark_type": "https://tm.example/t", "trust_mark": "a.b.c"}]
    entity = federation.resolve_via_trust_anchors(fed.network(trust_marks=marks), LEAF, fed.trust_anchors())
    assert entity.trust_marks == marks
    first = entity.trust_marks
    first.append("mutated")
    first[0]["trust_mark_type"] = "changed"
    assert entity.trust_marks == marks


def test_resolve_rejects_non_array_trust_marks(fed):
    with pytest.raises(pygrindvakt.GrindvaktError):
        federation.resolve_via_trust_anchors(fed.network(trust_marks={"not": "an array"}), LEAF, fed.trust_anchors())


def test_resolved_entity_exp_bounded_by_chain(fed):
    """exp is the min of the resolve response exp and the earliest chain statement exp."""
    short = now() + 600
    claims = {"iss": TA, "sub": LEAF, "iat": now(), "exp": short, "jwks": fed.leaf_key.to_public_jwks()}
    sub_short = jwt.sign(fed.ta_key, claims, typ=federation.ENTITY_STATEMENT_TYP)
    chain = [fed.leaf_ec, sub_short, fed.ta_ec]
    http = fed.network(chain=chain, resolve_exp=now() + 7200)
    entity = federation.resolve_via_trust_anchors(http, LEAF, fed.trust_anchors())
    assert entity.exp == short


def test_resolve_via_trust_anchors_success(fed):
    """A valid chain rooted at the configured TA yields the resolved entity."""
    http = fed.network()
    entity = federation.resolve_via_trust_anchors(http, LEAF, fed.trust_anchors())

    assert isinstance(entity, federation.ResolvedEntity)
    assert entity.subject == LEAF
    assert entity.issuer == TA
    assert entity.metadata == LEAF_METADATA
    assert entity.metadata["openid_relying_party"]["client_name"] == "RP"
    assert entity.subject_jwks == fed.leaf_key.to_public_jwks()
    assert entity.exp is not None and entity.exp > now()
    assert entity.trust_marks == []
    assert repr(entity).startswith(f'ResolvedEntity(issuer="{TA}", subject="{LEAF}", exp=Some(')

    # Only the TA's well-known and its resolve endpoint were contacted.
    assert http.calls[0] == TA + WELL_KNOWN
    assert len(http.calls) == 2
    parts = urlsplit(http.calls[1])
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == RESOLVE_EP
    query = parse_qs(parts.query)
    assert query == {"sub": [LEAF], "trust_anchor": [TA]}
    assert "sub=" + quote(LEAF, safe="") in http.calls[1]
    assert LEAF + WELL_KNOWN not in http.calls


def test_resolve_appends_to_existing_query(fed):
    """A resolve endpoint that already has a query string gets ``&`` appended."""
    ep = RESOLVE_EP + "?v=1"
    ta_ec = federation.build_entity_configuration(
        fed.ta_key,
        TA,
        fed.ta_key.to_public_jwks(),
        [],
        {"federation_entity": {"federation_resolve_endpoint": ep}},
        None,
        3600,
    )
    chain = [fed.leaf_ec, fed.subordinate, ta_ec]
    resolved = resolve_response(fed.ta_key, TA, LEAF, LEAF_METADATA, chain)
    http = FakeHttpClient(
        {
            TA + WELL_KNOWN: (200, ta_ec, "application/entity-statement+jwt"),
            RESOLVE_EP: (200, resolved, "application/resolve-response+jwt"),
        }
    )
    entity = federation.resolve_via_trust_anchors(http, LEAF, fed.trust_anchors())
    assert entity.subject == LEAF
    assert http.calls[1].startswith(ep + "&sub=")


def test_resolve_rejects_unknown_trust_anchor_keys(fed):
    """Configuring the TA with the wrong keys fails: nothing in the chain verifies."""
    http = fed.network()
    attacker = make_key("attacker")
    with pytest.raises(pygrindvakt.GrindvaktError):
        federation.resolve_via_trust_anchors(http, LEAF, {TA: attacker.to_public_jwks()})


def test_resolve_rejects_chain_signed_by_unknown_ta(fed):
    """A resolve response signed by a key the RP does not trust is refused."""
    attacker = make_key("attacker")
    http = fed.network(resolve_signer=attacker)
    with pytest.raises(pygrindvakt.GrindvaktError):
        federation.resolve_via_trust_anchors(http, LEAF, fed.trust_anchors())


def test_resolve_rejects_subordinate_statement_from_attacker(fed):
    """A subordinate statement not signed by the TA breaks the chain even if the response is TA-signed.

    The chain is ``[leaf EC, TA->leaf statement, TA EC]``; each element must
    verify against the *next* element's ``jwks``, so the forged statement at
    index 1 fails against the TA configuration's keys at index 2.
    """
    attacker = make_key("attacker")
    bad_sub = subordinate_statement(attacker, TA, LEAF, fed.leaf_key.to_public_jwks())
    http = fed.network(chain=[fed.leaf_ec, bad_sub, fed.ta_ec])
    with pytest.raises(pygrindvakt.AuthnError, match="trust_chain\\[1\\] signature failed"):
        federation.resolve_via_trust_anchors(http, LEAF, fed.trust_anchors())


def test_resolve_rejects_chain_not_starting_with_subject(fed):
    """The trust chain must start with the subject's entity configuration."""
    http = fed.network(chain=[fed.subordinate, fed.ta_ec])
    with pytest.raises(pygrindvakt.AuthnError, match="does not start with the subject"):
        federation.resolve_via_trust_anchors(http, LEAF, fed.trust_anchors())


def test_resolve_rejects_empty_and_missing_trust_chain(fed):
    """An empty ``trust_chain`` or none at all is an AuthnError."""
    http = fed.network(chain=[])
    with pytest.raises(pygrindvakt.AuthnError, match="trust_chain is empty"):
        federation.resolve_via_trust_anchors(http, LEAF, fed.trust_anchors())

    no_chain = jwt.sign(
        fed.ta_key,
        {"iss": TA, "sub": LEAF, "iat": now(), "exp": now() + 60, "metadata": {}},
        typ=federation.RESOLVE_RESPONSE_TYP,
    )
    http = FakeHttpClient(
        {
            TA + WELL_KNOWN: (200, fed.ta_ec, "application/entity-statement+jwt"),
            RESOLVE_EP: (200, no_chain, "application/resolve-response+jwt"),
        }
    )
    with pytest.raises(pygrindvakt.AuthnError, match="no trust_chain"):
        federation.resolve_via_trust_anchors(http, LEAF, fed.trust_anchors())


def test_resolve_rejects_sub_mismatch(fed):
    """A resolve response for a different subject is refused."""
    http = fed.network()
    with pytest.raises(pygrindvakt.AuthnError, match="sub mismatch"):
        federation.resolve_via_trust_anchors(http, "https://other.example", fed.trust_anchors())


def test_resolve_requires_resolve_endpoint_in_ta_configuration(fed):
    """A TA whose entity configuration lacks ``federation_resolve_endpoint`` cannot be used."""
    ta_ec = federation.build_entity_configuration(
        fed.ta_key,
        TA,
        fed.ta_key.to_public_jwks(),
        [],
        {"federation_entity": {}},
        None,
        3600,
    )
    http = FakeHttpClient({TA + WELL_KNOWN: (200, ta_ec, "application/entity-statement+jwt")})
    with pytest.raises(pygrindvakt.InternalError, match="no federation_resolve_endpoint"):
        federation.resolve_via_trust_anchors(http, LEAF, fed.trust_anchors())


def test_resolve_with_no_trust_anchors(fed):
    """An empty trust-anchor map fails before any network access."""
    http = fed.network()
    with pytest.raises(pygrindvakt.AuthnError, match="no trust anchors configured"):
        federation.resolve_via_trust_anchors(http, LEAF, {})
    assert http.calls == []


def test_resolve_tries_each_trust_anchor(fed):
    """A failing anchor is skipped; an anchor that succeeds wins (iteration order is unspecified)."""
    other_ta = "https://other-ta.example.org"
    http = fed.network()
    anchors = {
        other_ta: make_key("x").to_public_jwks(),
        TA: fed.ta_key.to_public_jwks(),
    }
    entity = federation.resolve_via_trust_anchors(http, LEAF, anchors)
    assert entity.issuer == TA
    assert all(c.startswith((TA, other_ta)) for c in http.calls)
    assert http.calls[-1].startswith(RESOLVE_EP + "?")

    # When every anchor fails, the error of the last one tried is raised.
    anchors = {
        other_ta: make_key("x").to_public_jwks(),
        "https://third.example": make_key("y").to_public_jwks(),
    }
    with pytest.raises(pygrindvakt.InternalError, match="returned 404"):
        federation.resolve_via_trust_anchors(http, LEAF, anchors)


def test_resolve_response_non_200(fed):
    """A non-200 from the resolve endpoint is an InternalError naming the status."""
    http = FakeHttpClient({TA + WELL_KNOWN: (200, fed.ta_ec, "application/entity-statement+jwt")})
    with pytest.raises(pygrindvakt.InternalError, match="returned 404"):
        federation.resolve_via_trust_anchors(http, LEAF, fed.trust_anchors())


def test_trust_anchors_must_be_a_jwks_map(fed):
    """``trust_anchors`` values must be ``{"keys": [...]}`` dicts."""
    with pytest.raises(TypeError):
        federation.resolve_via_trust_anchors(fed.network(), LEAF, {TA: "not-a-jwks"})


# ---------------------------------------------------------------------------
# entity_metadata_jwks / fetch_signed_jwks
# ---------------------------------------------------------------------------


def test_entity_metadata_jwks_inline(fed):
    """Inline ``jwks`` wins and no request is made."""
    http = FakeHttpClient({})
    jwks = fed.leaf_key.to_public_jwks()
    out = federation.entity_metadata_jwks(http, {"jwks": jwks}, LEAF, fed.leaf_key.to_public_jwks())
    assert out == jwks
    assert http.calls == []


def test_entity_metadata_jwks_via_jwks_uri(fed):
    """``jwks_uri`` is fetched as plain JSON."""
    jwks = fed.leaf_key.to_public_jwks()
    http = FakeHttpClient({LEAF + "/jwks": (200, json.dumps(jwks), "application/json")})
    out = federation.entity_metadata_jwks(http, {"jwks_uri": LEAF + "/jwks"}, LEAF, fed.leaf_key.to_public_jwks())
    assert out == jwks
    assert http.calls == [LEAF + "/jwks"]

    http = FakeHttpClient({})
    with pytest.raises(pygrindvakt.InternalError, match="jwks fetch failed"):
        federation.entity_metadata_jwks(http, {"jwks_uri": LEAF + "/jwks"}, LEAF, fed.leaf_key.to_public_jwks())


def test_entity_metadata_jwks_via_signed_jwks_uri(fed):
    """``signed_jwks_uri`` is verified against the subject's federation keys."""
    op_key = make_key("op-sig")
    doc = signed_jwks_document(fed.leaf_key, LEAF, op_key.to_public_jwks()["keys"])
    http = FakeHttpClient({LEAF + "/signed-jwks": (200, doc, "application/jwk-set+jwt")})
    out = federation.entity_metadata_jwks(
        http,
        {"signed_jwks_uri": LEAF + "/signed-jwks"},
        LEAF,
        fed.leaf_key.to_public_jwks(),
    )
    assert out == op_key.to_public_jwks()
    assert http.calls == [LEAF + "/signed-jwks"]


def test_entity_metadata_jwks_prefers_signed_over_plain_uri(fed):
    """When both URIs are present the signed one is used."""
    doc = signed_jwks_document(fed.leaf_key, LEAF, fed.leaf_key.to_public_jwks()["keys"])
    http = FakeHttpClient(
        {
            LEAF + "/signed-jwks": (200, doc, "application/jwk-set+jwt"),
            LEAF + "/jwks": (200, "{}", "application/json"),
        }
    )
    federation.entity_metadata_jwks(
        http,
        {"signed_jwks_uri": LEAF + "/signed-jwks", "jwks_uri": LEAF + "/jwks"},
        LEAF,
        fed.leaf_key.to_public_jwks(),
    )
    assert http.calls == [LEAF + "/signed-jwks"]


def test_entity_metadata_jwks_without_any_source(fed):
    """Metadata with no key source is an AuthnError."""
    with pytest.raises(pygrindvakt.AuthnError, match="neither jwks"):
        federation.entity_metadata_jwks(FakeHttpClient({}), {"issuer": LEAF}, LEAF, fed.leaf_key.to_public_jwks())


def test_entity_metadata_jwks_malformed_inline_does_not_fall_back(fed):
    """A malformed inline ``jwks`` fails instead of downgrading to ``jwks_uri``."""
    http = FakeHttpClient({LEAF + "/jwks": (200, "{}", "application/json")})
    with pytest.raises(pygrindvakt.GrindvaktError):
        federation.entity_metadata_jwks(
            http,
            {"jwks": "not-a-jwks", "jwks_uri": LEAF + "/jwks"},
            LEAF,
            fed.leaf_key.to_public_jwks(),
        )
    assert http.calls == []


def test_fetch_signed_jwks_checks(fed):
    """``fetch_signed_jwks`` enforces status, content type, signer, ``sub`` and ``typ``."""
    op_key = make_key("op-sig")
    good = signed_jwks_document(fed.leaf_key, LEAF, op_key.to_public_jwks()["keys"])
    uri = LEAF + "/signed-jwks"
    fed_jwks = fed.leaf_key.to_public_jwks()

    out = federation.fetch_signed_jwks(
        FakeHttpClient({uri: (200, good, "application/jwk-set+jwt; charset=utf-8")}),
        uri,
        LEAF,
        fed_jwks,
    )
    assert out == op_key.to_public_jwks()

    # Missing content type is tolerated.
    assert federation.fetch_signed_jwks(FakeHttpClient({uri: (200, good, None)}), uri, LEAF, fed_jwks)

    with pytest.raises(pygrindvakt.InternalError, match="404"):
        federation.fetch_signed_jwks(FakeHttpClient({}), uri, LEAF, fed_jwks)

    with pytest.raises(pygrindvakt.AuthnError, match="unexpected content type"):
        federation.fetch_signed_jwks(FakeHttpClient({uri: (200, good, "application/json")}), uri, LEAF, fed_jwks)

    with pytest.raises(pygrindvakt.AuthnError, match="sub mismatch"):
        federation.fetch_signed_jwks(
            FakeHttpClient({uri: (200, good, "application/jwk-set+jwt")}),
            uri,
            "https://other.example",
            fed_jwks,
        )

    # Signed by a key that is not the subject's federation key.
    forged = signed_jwks_document(make_key("mallory"), LEAF, op_key.to_public_jwks()["keys"])
    with pytest.raises(pygrindvakt.GrindvaktError):
        federation.fetch_signed_jwks(
            FakeHttpClient({uri: (200, forged, "application/jwk-set+jwt")}),
            uri,
            LEAF,
            fed_jwks,
        )

    # Wrong typ (an entity statement instead of a jwk-set document).
    with pytest.raises(pygrindvakt.GrindvaktError):
        federation.fetch_signed_jwks(
            FakeHttpClient({uri: (200, fed.leaf_ec, "application/jwk-set+jwt")}),
            uri,
            LEAF,
            fed_jwks,
        )

    # No ``keys`` member.
    no_keys = jwt.sign(
        fed.leaf_key,
        {"iss": LEAF, "sub": LEAF, "iat": now(), "exp": now() + 60},
        typ=federation.JWK_SET_TYP,
    )
    with pytest.raises(pygrindvakt.AuthnError, match="no keys"):
        federation.fetch_signed_jwks(
            FakeHttpClient({uri: (200, no_keys, "application/jwk-set+jwt")}),
            uri,
            LEAF,
            fed_jwks,
        )


# ---------------------------------------------------------------------------
# Collection endpoint
# ---------------------------------------------------------------------------

COLLECTION_BODY = {
    "entities": [
        {
            # openid_provider UI is empty -> fall back to federation_entity.
            "entity_id": "https://op-a.example",
            "entity_types": ["openid_provider", "federation_entity"],
            "ui_infos": {
                "federation_entity": {
                    "display_name": "OP A Org",
                    "logo_uri": "https://op-a.example/logo.svg",
                },
                "openid_provider": {"display_name": None, "logo_uri": None},
            },
        },
        {
            # openid_provider UI wins when present.
            "entity_id": "https://op-b.example",
            "entity_types": ["openid_provider"],
            "ui_infos": {
                "openid_provider": {
                    "display_name": "OP B",
                    "logo_uri": "https://op-b.example/b.png",
                }
            },
        },
        {
            # No UI at all -> display_name defaults to the entity id.
            "entity_id": "https://op-c.example",
            "entity_types": ["openid_provider"],
        },
        {
            # Wrong entity type -> filtered out.
            "entity_id": "https://rp.example",
            "entity_types": ["openid_relying_party"],
            "ui_infos": {"openid_relying_party": {"display_name": "An RP"}},
        },
        {
            # Empty entity id -> skipped.
            "entity_id": "",
            "entity_types": ["openid_provider"],
        },
    ]
}

EXPECTED_OPS = [
    federation.CollectionEntity(
        entity_id="https://op-a.example",
        display_name="OP A Org",
        logo_uri="https://op-a.example/logo.svg",
    ),
    federation.CollectionEntity(
        entity_id="https://op-b.example",
        display_name="OP B",
        logo_uri="https://op-b.example/b.png",
    ),
    federation.CollectionEntity(entity_id="https://op-c.example", display_name="https://op-c.example"),
]


def test_collection_entity_value_semantics():
    """CollectionEntity is a keyword-only frozen value type with structural equality."""
    a = federation.CollectionEntity(entity_id="https://op.example", display_name="OP")
    b = federation.CollectionEntity(entity_id="https://op.example", display_name="OP", logo_uri=None)
    c = federation.CollectionEntity(entity_id="https://op.example", display_name="OP", logo_uri="x")
    assert a == b
    assert a != c
    assert a != "https://op.example"
    assert (a == object()) is False  # exercises __eq__ itself, not the __ne__ path
    assert a.entity_id == "https://op.example"
    assert a.display_name == "OP"
    assert a.logo_uri is None
    assert c.logo_uri == "x"
    assert repr(c) == 'CollectionEntity(entity_id="https://op.example", display_name="OP", logo_uri=Some("x"))'
    with pytest.raises(TypeError):
        federation.CollectionEntity("https://op.example", "OP")
    with pytest.raises(AttributeError):
        a.entity_id = "other"


def test_parse_collection_flattens_ui_with_fallbacks():
    """Mirrors upstream: per-type UI with display_name/logo fallbacks and type filtering."""
    ops = federation.parse_collection(COLLECTION_BODY, "openid_provider")
    assert ops == EXPECTED_OPS
    assert [o.entity_id for o in ops] == [
        "https://op-a.example",
        "https://op-b.example",
        "https://op-c.example",
    ]
    rps = federation.parse_collection(COLLECTION_BODY, "openid_relying_party")
    assert rps == [federation.CollectionEntity(entity_id="https://rp.example", display_name="An RP")]


def test_parse_collection_handles_missing_entities():
    """A body without ``entities`` (or with an empty list) yields an empty list."""
    assert federation.parse_collection({}, "openid_provider") == []
    assert federation.parse_collection({"entities": []}, "openid_provider") == []
    assert federation.parse_collection({"entities": "nope"}, "openid_provider") == []


def test_parse_collection_requires_explicit_entity_type_membership():
    """Entities that do not list the requested type in ``entity_types`` are dropped."""
    body = {
        "entities": [
            {"entity_id": "https://typed.example", "entity_types": ["openid_provider"]},
            {
                "entity_id": "https://untyped.example",
                "ui_infos": {"openid_provider": {"display_name": "Untyped OP"}},
            },
        ]
    }
    ops = federation.parse_collection(body, "openid_provider")
    assert len(ops) == 1
    assert ops[0].entity_id == "https://typed.example"


def test_fetch_collection_through_fake_client():
    """``fetch_collection`` appends ``entity_type`` to the endpoint and parses the JSON body."""
    endpoint = TA + "/collection"
    http = FakeHttpClient({endpoint: (200, json.dumps(COLLECTION_BODY), "application/json")})
    ops = federation.fetch_collection(http, endpoint, "openid_provider")
    assert ops == EXPECTED_OPS
    assert http.calls == [endpoint + "?entity_type=openid_provider"]

    # Existing query string -> '&'.
    http = FakeHttpClient({endpoint: (200, json.dumps(COLLECTION_BODY), "application/json")})
    federation.fetch_collection(http, endpoint + "?page=1", "openid_provider")
    assert http.calls == [endpoint + "?page=1&entity_type=openid_provider"]

    # Entity type is URL-encoded.
    http = FakeHttpClient({endpoint: (200, "{}", "application/json")})
    assert federation.fetch_collection(http, endpoint, "a b&c") == []
    assert http.calls == [endpoint + "?entity_type=a+b%26c"]


def test_fetch_collection_errors():
    """Non-200 responses and non-JSON bodies raise GrindvaktError."""
    endpoint = TA + "/collection"
    with pytest.raises(pygrindvakt.InternalError, match="returned 404"):
        federation.fetch_collection(FakeHttpClient({}), endpoint, "openid_provider")
    http = FakeHttpClient({endpoint: (200, "not json", "text/plain")})
    with pytest.raises(pygrindvakt.GrindvaktError):
        federation.fetch_collection(http, endpoint, "openid_provider")


# ---------------------------------------------------------------------------
# Metadata policy
# ---------------------------------------------------------------------------


def test_apply_policy_operators_mirror_upstream():
    """value/default/subset_of/one_of as in the upstream unit test; the input is left untouched."""
    metadata = {"scopes": ["openid", "email"], "subject_type": "public"}
    policy = {
        "client_registration_types": {"default": ["automatic"]},
        "scopes": {"subset_of": ["openid", "email", "profile"]},
        "subject_type": {"one_of": ["public", "pairwise"]},
        "id_token_signed_response_alg": {"value": "ES256"},
    }
    out = federation.apply_policy(metadata, policy)
    assert out == {
        "scopes": ["openid", "email"],
        "subject_type": "public",
        "client_registration_types": ["automatic"],
        "id_token_signed_response_alg": "ES256",
    }
    # Copy-in / copy-out: the caller's dict is not mutated.
    assert metadata == {"scopes": ["openid", "email"], "subject_type": "public"}


def test_apply_policy_value_overrides_and_default_does_not():
    """``value`` forces the parameter; ``default`` only fills an absent one."""
    out = federation.apply_policy(
        {"a": 1, "b": 2},
        {"a": {"value": 10}, "b": {"default": 20}, "c": {"default": 30}},
    )
    assert out == {"a": 10, "b": 2, "c": 30}


def test_apply_policy_add_appends_unique_values():
    """``add`` appends values not already present, creating the array if needed."""
    out = federation.apply_policy(
        {"scopes": ["openid"]},
        {
            "scopes": {"add": ["openid", "email"]},
            "grant_types": {"add": "authorization_code"},
        },
    )
    assert out == {"scopes": ["openid", "email"], "grant_types": ["authorization_code"]}


def test_apply_policy_one_of():
    """``one_of`` constrains a present scalar; an absent parameter passes."""
    assert federation.apply_policy({"x": "b"}, {"x": {"one_of": ["a", "b"]}}) == {"x": "b"}
    assert federation.apply_policy({}, {"x": {"one_of": ["a", "b"]}}) == {}
    with pytest.raises(pygrindvakt.AuthnError, match="not in one_of"):
        federation.apply_policy({"x": "c"}, {"x": {"one_of": ["a", "b"]}})


def test_apply_policy_subset_of():
    """``subset_of`` requires every present value to be allowed."""
    with pytest.raises(pygrindvakt.AuthnError, match="subset_of"):
        federation.apply_policy({"scopes": ["openid", "evil"]}, {"scopes": {"subset_of": ["openid"]}})
    assert federation.apply_policy({}, {"scopes": {"subset_of": ["openid"]}}) == {}


def test_apply_policy_superset_of():
    """``superset_of`` requires every listed value to be present (absent -> violation)."""
    ok = federation.apply_policy({"scopes": ["openid", "email"]}, {"scopes": {"superset_of": ["openid"]}})
    assert ok["scopes"] == ["openid", "email"]
    with pytest.raises(pygrindvakt.AuthnError, match="superset_of"):
        federation.apply_policy({"scopes": ["email"]}, {"scopes": {"superset_of": ["openid"]}})
    with pytest.raises(pygrindvakt.AuthnError, match="superset_of"):
        federation.apply_policy({}, {"scopes": {"superset_of": ["openid"]}})


def test_apply_policy_essential():
    """``essential: true`` fails when the parameter is absent after value/default/add."""
    with pytest.raises(pygrindvakt.AuthnError, match="essential parameter jwks"):
        federation.apply_policy({}, {"jwks": {"essential": True}})
    assert federation.apply_policy({}, {"jwks": {"essential": False}}) == {}
    # A default satisfies essential.
    assert federation.apply_policy({}, {"x": {"default": 1, "essential": True}}) == {"x": 1}


def test_apply_policy_rejects_non_object_operator():
    """A policy entry that is not an object is a BadRequestError."""
    with pytest.raises(pygrindvakt.BadRequestError, match="not an object"):
        federation.apply_policy({}, {"x": "value"})


def test_apply_policy_requires_dicts():
    """Both arguments must be JSON objects."""
    with pytest.raises(TypeError):
        federation.apply_policy(["not", "a", "dict"], {})
    with pytest.raises(TypeError):
        federation.apply_policy({}, ["not", "a", "dict"])


OCT_KEY = {"kty": "oct", "k": "c" * 43, "kid": "sym"}


def test_entity_metadata_jwks_inline_drops_oct_keys_with_warning(fed):
    """OIDC Core 10.1: symmetric keys in published (inline) metadata are dropped."""
    pub = fed.leaf_key.to_public_jwks()
    http = FakeHttpClient({})
    with pytest.warns(UserWarning, match=r"symmetric \(oct\) key, ignored"):
        out = federation.entity_metadata_jwks(http, {"jwks": {"keys": [*pub["keys"], OCT_KEY]}}, LEAF, pub)
    assert out == pub


def test_entity_metadata_jwks_uppercase_oct_kty_dropped(fed):
    pub = fed.leaf_key.to_public_jwks()
    with pytest.warns(UserWarning, match="symmetric"):
        out = federation.entity_metadata_jwks(
            FakeHttpClient({}), {"jwks": {"keys": [*pub["keys"], {**OCT_KEY, "kty": "OCT"}]}}, LEAF, pub
        )
    assert out == pub


def test_oct_drop_is_unconditional_when_warnings_are_errors(fed):
    """A warning filter set to "error" is swallowed; the key is dropped regardless."""
    pub = fed.leaf_key.to_public_jwks()
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        out = federation.entity_metadata_jwks(
            FakeHttpClient({}), {"jwks": {"keys": [*pub["keys"], OCT_KEY]}}, LEAF, pub
        )
    assert out == pub


def test_entity_metadata_jwks_signed_uri_drops_oct_keys(fed):
    pub = fed.leaf_key.to_public_jwks()
    doc = signed_jwks_document(fed.leaf_key, LEAF, [*pub["keys"], OCT_KEY])
    http = FakeHttpClient({LEAF + "/signed-jwks": (200, doc, "application/jwk-set+jwt")})
    with pytest.warns(UserWarning, match="symmetric"):
        out = federation.entity_metadata_jwks(http, {"signed_jwks_uri": LEAF + "/signed-jwks"}, LEAF, pub)
    assert out == pub


def test_fetch_signed_jwks_drops_oct_keys_with_warning(fed):
    pub = fed.leaf_key.to_public_jwks()
    uri = LEAF + "/signed-jwks"
    doc = signed_jwks_document(fed.leaf_key, LEAF, [OCT_KEY, *pub["keys"]])
    with pytest.warns(UserWarning, match=r"symmetric \(oct\) key, ignored"):
        out = federation.fetch_signed_jwks(FakeHttpClient({uri: (200, doc, None)}), uri, LEAF, pub)
    assert out == pub


# ---------------------------------------------------------------------------
# F1: no federation entry point verifies with a symmetric key (ADR 0006)
# ---------------------------------------------------------------------------

HS_SECRET = "c" * 43
HS_JWK = {"kty": "oct", "k": HS_SECRET, "kid": "sym"}
SYM = r"symmetric \(oct\) key, ignored"


def hs256_key():
    return keys.signing_key_from_jwk({"kty": "oct", "k": HS_SECRET, "kid": "sym"}, alg="HS256", kid="sym")


def attacker_ec_jwk() -> dict:
    return make_key("evil").to_public_jwks()["keys"][0]


def test_fetch_signed_jwks_refuses_hs256_signed_document_with_oct_verifier_key(fed):
    uri = LEAF + "/signed-jwks"
    doc = signed_jwks_document(hs256_key(), LEAF, [attacker_ec_jwk()])
    http = FakeHttpClient({uri: (200, doc, None)})
    with pytest.warns(UserWarning, match=SYM), pytest.raises(pygrindvakt.GrindvaktError):
        federation.fetch_signed_jwks(http, uri, LEAF, {"keys": [HS_JWK]})


def test_entity_metadata_jwks_signed_uri_refuses_hs256_document(fed):
    uri = LEAF + "/signed-jwks"
    doc = signed_jwks_document(hs256_key(), LEAF, [attacker_ec_jwk()])
    http = FakeHttpClient({uri: (200, doc, None)})
    with pytest.warns(UserWarning, match=SYM), pytest.raises(pygrindvakt.GrindvaktError):
        federation.entity_metadata_jwks(http, {"signed_jwks_uri": uri}, LEAF, {"keys": [HS_JWK]})


def test_verify_refuses_hs256_statement_with_oct_set(fed):
    token = jwt.sign(hs256_key(), {"iss": LEAF, "sub": LEAF, "exp": now() + 60}, typ=federation.ENTITY_STATEMENT_TYP)
    with pytest.raises(pygrindvakt.AuthnError) as ei:
        federation.verify(token, {"keys": [HS_JWK]})
    assert ei.value.code == "symmetric_algorithm"
    with pytest.raises(pygrindvakt.AuthnError) as ei:
        federation.verify_typed(token, fed.ta_key.to_public_jwks(), federation.ENTITY_STATEMENT_TYP)
    assert ei.value.code == "symmetric_algorithm"


def test_verify_self_signed_refuses_hs256_statement(fed):
    token = jwt.sign(
        hs256_key(),
        {"iss": LEAF, "sub": LEAF, "exp": now() + 60, "jwks": {"keys": [HS_JWK]}},
        typ=federation.ENTITY_STATEMENT_TYP,
    )
    with pytest.raises(pygrindvakt.AuthnError) as ei:
        federation.verify_self_signed(token)
    assert ei.value.code == "symmetric_algorithm"


def test_trust_anchor_map_with_oct_key_does_not_verify_hs_statements(fed):
    ta_ec = jwt.sign(
        hs256_key(),
        {"iss": TA, "sub": TA, "exp": now() + 60, "jwks": {"keys": [HS_JWK]}},
        typ=federation.ENTITY_STATEMENT_TYP,
    )
    resolved = resolve_response(hs256_key(), TA, LEAF, LEAF_METADATA, [fed.leaf_ec, fed.subordinate, ta_ec])
    http = FakeHttpClient(
        {
            TA + WELL_KNOWN: (200, ta_ec, None),
            RESOLVE_EP: (200, resolved, None),
        }
    )
    with pytest.warns(UserWarning, match=SYM), pytest.raises(pygrindvakt.GrindvaktError):
        federation.resolve_via_trust_anchors(http, LEAF, {TA: {"keys": [HS_JWK]}})


def test_entity_statement_jwks_getter_drops_oct_keys_with_warning(fed):
    pub = fed.leaf_key.to_public_jwks()
    token = jwt.sign(
        fed.ta_key,
        {"iss": TA, "sub": LEAF, "exp": now() + 60, "jwks": {"keys": [*pub["keys"], HS_JWK]}},
        typ=federation.ENTITY_STATEMENT_TYP,
    )
    stmt = federation.decode_unverified(token)
    with pytest.warns(UserWarning, match=SYM):
        assert stmt.jwks() == pub


def test_resolved_entity_subject_jwks_drops_oct_keys_with_warning(fed):
    pub = fed.leaf_key.to_public_jwks()
    with pytest.warns(UserWarning, match="publishing a symmetric"):
        leaf_ec = federation.build_entity_configuration(
            fed.leaf_key, LEAF, {"keys": [*pub["keys"], HS_JWK]}, [TA], LEAF_METADATA, None, 3600
        )
    sub = subordinate_statement(fed.ta_key, TA, LEAF, pub)
    resolved = resolve_response(fed.ta_key, TA, LEAF, LEAF_METADATA, [leaf_ec, sub, fed.ta_ec])
    http = FakeHttpClient(
        {
            TA + WELL_KNOWN: (200, fed.ta_ec, None),
            RESOLVE_EP: (200, resolved, None),
        }
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        entity = federation.resolve_via_trust_anchors(http, LEAF, fed.trust_anchors())
    with pytest.warns(UserWarning, match=SYM):
        assert entity.subject_jwks == pub


def test_clean_key_sets_verify_without_warning(fed):
    pub = fed.leaf_key.to_public_jwks()
    uri = LEAF + "/signed-jwks"
    doc = signed_jwks_document(fed.leaf_key, LEAF, pub["keys"])
    http = FakeHttpClient({uri: (200, doc, None)})
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert federation.fetch_signed_jwks(http, uri, LEAF, pub) == pub
        assert federation.entity_metadata_jwks(http, {"signed_jwks_uri": uri}, LEAF, pub) == pub
        assert federation.verify(fed.ta_ec, fed.ta_key.to_public_jwks()).iss() == TA
        assert federation.decode_unverified(fed.subordinate).jwks() == pub
        entity = federation.resolve_via_trust_anchors(fed.network(), LEAF, fed.trust_anchors())
        assert entity.subject_jwks == pub
    assert caught == []


def test_build_entity_configuration_warns_when_publishing_oct_key_but_signs(fed):
    pub = fed.leaf_key.to_public_jwks()
    with pytest.warns(UserWarning, match=r"publishing a symmetric \(oct\) key"):
        token = federation.build_entity_configuration(
            fed.leaf_key, LEAF, {"keys": [*pub["keys"], OCT_KEY]}, [TA], LEAF_METADATA
        )
    assert jwt.peek_claims_unverified(token)["jwks"]["keys"][-1]["kty"] == "oct"


def test_build_entity_configuration_no_warning_for_asymmetric_keys(fed):
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        federation.build_entity_configuration(fed.leaf_key, LEAF, fed.leaf_key.to_public_jwks(), [TA], LEAF_METADATA)
    assert caught == []


# ---------------------------------------------------------------------------
# verify_trust_marks
# ---------------------------------------------------------------------------

TM_TYPE = "https://tm.example/t"
TM_ISSUER = "https://tmi.example.org"


def trust_mark(signer, *, typ=federation.TRUST_MARK_TYP, **overrides) -> str:
    claims = {
        "iss": TM_ISSUER,
        "sub": LEAF,
        "trust_mark_type": TM_TYPE,
        "iat": now(),
        "exp": now() + 3600,
    }
    claims.update(overrides)
    for k in [k for k, v in claims.items() if v is None]:
        del claims[k]
    return jwt.sign(signer, claims, typ=typ)


def entry(token: str, type_: str = TM_TYPE) -> dict:
    return {"trust_mark_type": type_, "trust_mark": token}


def verify_marks(fed, marks, **kw):
    kw.setdefault("subject", LEAF)
    return federation.verify_trust_marks(marks, fed.ta_key.to_public_jwks(), TM_TYPE, **kw)


def assert_invalid(fed, marks, code="trust_mark_invalid", **kw):
    with pytest.raises(pygrindvakt.AuthnError) as exc:
        verify_marks(fed, marks, **kw)
    assert exc.value.code == code


def test_trust_mark_typ_constant():
    assert federation.TRUST_MARK_TYP == "trust-mark+jwt"


def test_verify_trust_marks_round_trip_via_resolve(fed):
    marks = [entry(trust_mark(fed.ta_key))]
    entity = federation.resolve_via_trust_anchors(fed.network(trust_marks=marks), LEAF, fed.trust_anchors())
    out = federation.verify_trust_marks(
        entity.trust_marks, fed.ta_key.to_public_jwks(), TM_TYPE, subject=entity.subject, issuer=TM_ISSUER
    )
    assert len(out) == 1
    assert out[0].iss() == TM_ISSUER
    assert out[0].sub() == LEAF
    assert out[0].claims["trust_mark_type"] == TM_TYPE


def test_verify_trust_marks_wrong_typ(fed):
    assert_invalid(fed, [entry(trust_mark(fed.ta_key, typ="JWT"))])


def test_verify_trust_marks_wrong_subject(fed):
    assert_invalid(fed, [entry(trust_mark(fed.ta_key, sub="https://other.example"))])


def test_verify_trust_marks_issuer_mismatch(fed):
    assert_invalid(fed, [entry(trust_mark(fed.ta_key))], issuer="https://else.example")


def test_verify_trust_marks_issuer_match(fed):
    assert len(verify_marks(fed, [entry(trust_mark(fed.ta_key))], issuer=TM_ISSUER)) == 1


def test_verify_trust_marks_wrong_key(fed):
    assert_invalid(fed, [entry(trust_mark(make_key("other")))])


def test_verify_trust_marks_expired(fed):
    assert_invalid(fed, [entry(trust_mark(fed.ta_key, exp=now() - 600, iat=now() - 1200))])


def test_verify_trust_marks_future_nbf(fed):
    assert_invalid(fed, [entry(trust_mark(fed.ta_key, nbf=now() + 600))])


def test_verify_trust_marks_missing_exp(fed):
    tok = trust_mark(fed.ta_key, exp=None)
    assert_invalid(fed, [entry(tok)])
    assert_invalid(fed, [entry(tok)], require_exp=True)
    assert len(verify_marks(fed, [entry(tok)], require_exp=False)) == 1


def test_verify_trust_marks_hs256_refused(fed):
    hs = keys.signing_key_from_jwk({"kty": "oct", "k": "c" * 43, "kid": "sym"}, alg="HS256", kid="sym")
    assert_invalid(fed, [entry(trust_mark(hs))], code="symmetric_algorithm")


def test_verify_trust_marks_missing_iat(fed):
    """OpenID Federation 1.0 section 7.1: ``iat`` is REQUIRED."""
    assert_invalid(fed, [entry(trust_mark(fed.ta_key, iat=None))])


@pytest.mark.parametrize("alg", ["HS256", "none"])
@pytest.mark.parametrize("bad_first", [True, False])
def test_verify_trust_marks_mac_entry_does_not_hide_valid_mark(fed, alg, bad_first):
    good = entry(trust_mark(fed.ta_key))
    if alg == "none":
        hdr = base64.urlsafe_b64encode(b'{"alg":"none","typ":"trust-mark+jwt"}').rstrip(b"=").decode()
        body = base64.urlsafe_b64encode(b"{}").rstrip(b"=").decode()
        bad = entry(f"{hdr}.{body}.")
    else:
        hs = keys.signing_key_from_jwk({"kty": "oct", "k": "c" * 43, "kid": "sym"}, alg="HS256", kid="sym")
        bad = entry(trust_mark(hs))
    marks = [bad, good] if bad_first else [good, bad]
    assert len(verify_marks(fed, marks)) == 1
    assert_invalid(fed, [bad], code="symmetric_algorithm")


def test_verify_trust_marks_inner_type_mismatch(fed):
    assert_invalid(fed, [entry(trust_mark(fed.ta_key, trust_mark_type="https://tm.example/other"))])


def test_verify_trust_marks_outer_type_mismatch(fed):
    """The entry claims another type than the signed mark: skipped, so nothing of the type exists."""
    tok = trust_mark(fed.ta_key, trust_mark_type="https://tm.example/other")
    assert_invalid(fed, [entry(tok, "https://tm.example/other")], code="trust_mark_missing")


def test_verify_trust_marks_missing_iss(fed):
    assert_invalid(fed, [entry(trust_mark(fed.ta_key, iss=None))])


def test_verify_trust_marks_delegation_fails_closed(fed):
    assert_invalid(fed, [entry(trust_mark(fed.ta_key, delegation="a.b.c"))])


def test_verify_trust_marks_non_dict_entry_ignored(fed):
    assert_invalid(fed, ["not a dict", 5, None], code="trust_mark_missing")
    assert len(verify_marks(fed, ["junk", entry(trust_mark(fed.ta_key))])) == 1


def test_verify_trust_marks_entry_without_trust_mark(fed):
    assert_invalid(fed, [{"trust_mark_type": TM_TYPE}])
    assert_invalid(fed, [{"trust_mark_type": TM_TYPE, "trust_mark": 5}])


def test_verify_trust_marks_oct_key_dropped(fed):
    jwks = {"keys": [OCT_KEY]}
    with pytest.warns(UserWarning, match=r"symmetric \(oct\) key"), pytest.raises(pygrindvakt.AuthnError) as exc:
        federation.verify_trust_marks([entry(trust_mark(fed.ta_key))], jwks, TM_TYPE, subject=LEAF)
    assert exc.value.code == "trust_mark_invalid"


def test_verify_trust_marks_other_types_skipped(fed):
    other = entry(trust_mark(make_key("x"), trust_mark_type="https://tm.example/o"), "https://tm.example/o")
    out = verify_marks(fed, [other, entry(trust_mark(fed.ta_key))])
    assert len(out) == 1


def test_verify_trust_marks_multiple_valid_all_returned(fed):
    marks = [entry(trust_mark(fed.ta_key, iss=f"https://i{n}.example")) for n in range(2)]
    out = verify_marks(fed, marks)
    assert [s.iss() for s in out] == ["https://i0.example", "https://i1.example"]


def test_verify_trust_marks_one_bad_one_good(fed):
    marks = [entry(trust_mark(make_key("bad"))), entry(trust_mark(fed.ta_key))]
    assert len(verify_marks(fed, marks)) == 1


def test_verify_trust_marks_none_of_type_is_missing(fed):
    assert_invalid(fed, [], code="trust_mark_missing")
    assert_invalid(fed, [entry("a.b.c", "https://tm.example/o")], code="trust_mark_missing")
