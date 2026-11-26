OpenID Federation
=================

OpenID Federation 1.1 lets an RP and an OP that have never exchanged
credentials trust each other through a chain of signed statements rooted at a
**trust anchor** both sides are configured to trust. Each entity publishes a
self-signed *entity configuration* at
``<entity_id>/.well-known/openid-federation``; intermediates and trust
anchors publish *subordinate statements* about the entities beneath them; a
trust anchor's *resolve endpoint* assembles and returns the whole chain with
metadata policy applied.

:mod:`pygrindvakt.federation` covers building and verifying entity statements,
resolving an entity through your configured trust anchors, fetching signed
JWK sets, the collection endpoint used by discovery pages, and the metadata
policy operators. :mod:`pygrindvakt.discovery` builds on it for
home-organization discovery. This guide walks through both sides of a
federation and then the OP-side pattern that makes it practical: automatic
client registration.

.. contents::
   :local:
   :depth: 1

Publishing an entity configuration
----------------------------------

Every participant, RP or OP, publishes an entity configuration: a JWT with
``iss == sub == entity_id``, ``typ = entity-statement+jwt``, its federation
signing keys, its ``authority_hints`` (the intermediates or trust anchors
that vouch for it) and its metadata per entity type.

.. code-block:: python

   from pygrindvakt import federation, keys
   from pygrindvakt.http import Response

   FED_KEY = keys.signing_key_from_pem(open("fed-key.pem", "rb").read(), kid="fed-1")
   ENTITY_ID = "https://rp.example.com"
   TRUST_ANCHOR = "https://ta.example.org"

   def entity_configuration() -> Response:
       jwt_ = federation.build_entity_configuration(
           FED_KEY,
           ENTITY_ID,
           FED_KEY.to_public_jwks(),
           [TRUST_ANCHOR],                            # authority_hints
           {
               "openid_relying_party": {
                   "client_name": "Example RP",
                   "redirect_uris": [f"{ENTITY_ID}/callback"],
                   "jwks": RP_CLIENT_KEY.to_public_jwks(),      # the private_key_jwt key
                   "token_endpoint_auth_method": "private_key_jwt",
                   "subject_type": "public",
               },
               "federation_entity": {"organization_name": "Example Org"},
           },
           trust_marks=None,
           lifetime=86400,
       )
       return Response(200, [("content-type", "application/entity-statement+jwt")], jwt_.encode())

Serve it at ``/.well-known/openid-federation`` on the entity id's host. An OP
publishes ``openid_provider`` metadata (its discovery document plus the
federation members) the same way. The federation key and the OIDC keys are
distinct: the federation key signs statements, the OIDC key signs id_tokens
or client assertions.

Verifying statements
--------------------

.. code-block:: python

   stmt = federation.verify_self_signed(token)          # entity configuration: keys from the token itself
   stmt = federation.verify(token, issuer_jwks)         # subordinate statement: keys of the issuer
   stmt = federation.verify_typed(token, ta_jwks, federation.RESOLVE_RESPONSE_TYP)

   stmt.iss(), stmt.sub(), stmt.authority_hints()
   stmt.jwks()                                           # {"keys": [...]} or BadRequestError
   stmt.metadata("openid_provider")                      # dict or None
   stmt.claims                                           # everything

All three verifiers require ``exp`` and the correct ``typ`` header.
:func:`~pygrindvakt.federation.decode_unverified` reads the claims without a
key for inspection, for example to learn an unknown entity's
``authority_hints``; never act on its output.

Trust anchors and resolution
----------------------------

Configuration consists of the trust anchors you accept, each with its
federation JWKS obtained out of band (the anchor's operator publishes it; you
pin it in configuration, not fetched at runtime):

.. code-block:: python

   TRUST_ANCHORS = {
       "https://ta.example.org": json.load(open("ta-example-org.jwks.json")),
       "https://ta.other.example": json.load(open("ta-other.jwks.json")),
   }

:func:`~pygrindvakt.federation.resolve_via_trust_anchors` resolves an
entity by delegating to each anchor's ``federation_resolve_endpoint``
(OpenID Federation section 10): it fetches and verifies the anchor's own
entity configuration against the pinned keys, calls
``<resolve_endpoint>?sub=...&trust_anchor=...``, verifies the resolve
response (``typ = resolve-response+jwt``, signed by the anchor) and fully
validates the ``trust_chain`` it carries: the chain starts with the
subject's entity configuration, ends at the anchor, and every subordinate
statement is signed by the entity above it. The first anchor that succeeds
wins; if all fail the last error is raised.

.. code-block:: python

   entity = federation.resolve_via_trust_anchors(None, "https://op.example.edu", TRUST_ANCHORS)
   entity.subject          # "https://op.example.edu"
   entity.issuer           # the trust anchor that answered
   entity.metadata         # policy-applied metadata, e.g. entity.metadata["openid_provider"]
   entity.subject_jwks     # the subject's federation keys
   entity.exp              # earlier of resolve and chain expiry; bound your cache by it
   entity.trust_marks      # raw entries; verify with verify_trust_marks

Trust marks
-----------

``entity.trust_marks`` is unverified. Do not test it with
``any(m["trust_mark_type"] == REQUIRED for m in entity.trust_marks)``: that
accepts a mark nobody signed. Use
:func:`~pygrindvakt.federation.verify_trust_marks` with the keys of the
trust mark *issuer* (the trust anchor only if it issues the mark itself):

.. code-block:: python

   marks = federation.verify_trust_marks(
       entity.trust_marks,
       MARK_ISSUER_JWKS,
       REQUIRED,
       subject=entity.subject,
       issuer=MARK_ISSUER_ID,
   )

.. warning::

   ``issuer`` is required, and ``MARK_ISSUER_JWKS`` must be keys you verified
   for that issuer. Never pass ``entity.subject_jwks``: the subject could then
   self-sign a mark (``iss == sub``) that verifies. Pinning ``issuer`` makes
   such a mark fail.

It raises ``AuthnError`` (``trust_mark_missing`` / ``trust_mark_invalid``)
unless at least one mark verifies. Marks without ``exp`` are rejected unless
``require_exp=False``.

Resolution is several HTTP round trips. Cache the result, keyed by subject,
for at most ``entity.exp - now`` seconds. ``exp`` is the earlier of the resolve
response's expiry and the earliest expiry in its validated trust chain.

Finding the OIDC keys of a resolved entity
------------------------------------------

An entity type's keys (the OP's id_token signing keys, the RP's
``private_key_jwt`` keys) come from its metadata in one of three ways:
inline ``jwks``, a ``signed_jwks_uri`` (a JWT of type ``jwk-set+jwt`` signed
with the entity's *federation* keys), or a plain ``jwks_uri``.
:func:`~pygrindvakt.federation.entity_metadata_jwks` tries them in that
order:

.. code-block:: python

   op_meta = entity.metadata["openid_provider"]
   op_jwks = federation.entity_metadata_jwks(None, op_meta, entity.subject, entity.subject_jwks)
   claims = rp.verify_id_token(op_jwks, id_token, entity.subject, my_client_id,
                               nonce, ["ES256"])

``entity.subject_jwks`` has any symmetric (``oct``) key dropped with a
``UserWarning``, and ``entity_metadata_jwks`` drops them from the key set it
verifies a ``signed_jwks_uri`` document with: federation entities sign with
asymmetric keys, and symmetric keys cannot be published.

Metadata policy
---------------

A resolve response already has the chain's policies applied. When you
process a chain yourself, :func:`~pygrindvakt.federation.apply_policy`
applies one policy object to one metadata object and returns the result
(the input is not modified). It supports ``value``, ``default``, ``add``,
``one_of``, ``subset_of``, ``superset_of`` and ``essential``, raising
:class:`pygrindvakt.AuthnError` when the metadata violates a constraint and
:class:`pygrindvakt.BadRequestError` for a malformed policy.

.. code-block:: python

   policy = {"scope": {"subset_of": ["openid", "email"]}, "token_endpoint_auth_method": {"value": "private_key_jwt"}}
   resolved = federation.apply_policy({"scope": ["openid", "email", "profile"]}, policy)
   # {"scope": ["openid", "email"], "token_endpoint_auth_method": "private_key_jwt"}

Discovery helpers: listing the OPs
----------------------------------

A trust anchor's collection endpoint lists the entities it knows, with UI
hints, which is what an RP's "choose your institution" page is built from.
:func:`~pygrindvakt.federation.fetch_collection` fetches and flattens it;
:func:`~pygrindvakt.federation.parse_collection` does the same for a body
you fetched yourself.

.. code-block:: python

   ops = federation.fetch_collection(None, "https://ta.example.org/collection", "openid_provider")
   for op_entry in ops:
       op_entry.entity_id, op_entry.display_name, op_entry.logo_uri

   found, ops = discovery.promote_hint(ops, request.args.get("hint", ""))   # preferred OP first

Display names and logo URLs come from the entities' own metadata and are
attacker-influenced within the federation: HTML-escape the names and allow
only ``https`` logos before rendering. :doc:`../api/discovery` documents the
rest of the discovery flow, including Third-Party Initiated Login.

OP side: automatic client registration
--------------------------------------

The pay-off for an OP is that any RP in the federation can log in without
being registered by hand. When an authorization request arrives from an
unknown ``client_id`` that looks like an entity identifier, the OP resolves
it through its trust anchors, builds a :class:`~pygrindvakt.client.Client`
from the resolved ``openid_relying_party`` metadata, and stores it with a TTL
bounded by the resolve response's ``exp``. This is the pattern tunnelbana's
federation front end implements in Rust; in Python it is a few lines around
:meth:`pygrindvakt.client.InMemoryClientStore.put_with_ttl`.

.. code-block:: python

   from pygrindvakt import OAuthError, client, federation, util
   from pygrindvakt.request import AuthorizationRequest

   RP_CACHE_TTL = 3600

   def auto_register(client_id: str) -> client.Client:
       """Resolve an unknown RP via the trust anchors and cache it as a client."""
       resolved = federation.resolve_via_trust_anchors(None, client_id, TRUST_ANCHORS)
       rp_meta = resolved.metadata.get("openid_relying_party")
       if rp_meta is None:
           raise OAuthError("invalid_client", "resolved metadata has no openid_relying_party")

       registered = client.Client(
           client_id,
           redirect_uris=[u for u in rp_meta.get("redirect_uris", []) if isinstance(u, str)],
           response_types=["code"],
           grant_types=["authorization_code"],
           token_endpoint_auth_method=client.AUTH_PRIVATE_KEY_JWT,
           jwks=rp_meta.get("jwks"),
           scope=rp_meta.get("scope"),
           # Public only: the binding has no pairwise support and Provider
           # refuses pairwise clients. Default to "public", never "pairwise".
           subject_type=rp_meta.get("subject_type", "public"),
           client_name=rp_meta.get("client_name"),
       )
       # Never trust the RP for longer than the trust anchor does.
       ttl = RP_CACHE_TTL
       if resolved.exp is not None:
           ttl = max(0, min(ttl, resolved.exp - util.now_secs()))
       op.clients.put_with_ttl(registered, ttl)
       return registered

   @app.get("/authorization")
   def authorization():
       data = request_data()
       try:
           req = AuthorizationRequest.from_params(data.query_pairs)
           if op.clients.get(req.client_id) is None and req.client_id.startswith("https://"):
               auto_register(req.client_id)
           op.validate_authorization_request(req)
       except OAuthError as e:
           return to_flask(e.to_response())
       except federation_errors as e:          # AuthnError, InternalError, ...
           log.warning("federation resolution failed for %s: %s", req.client_id, e)
           return to_flask(OAuthError("invalid_client", "unknown or unresolvable client").to_response())
       ...

Points worth noting:

* The resolved RP authenticates with ``private_key_jwt`` using the ``jwks``
  from its resolved metadata; there is no shared secret anywhere. Its
  authorization request must be a signed request object (``request``
  parameter) signed with one of those keys; unpack and verify it with
  :func:`pygrindvakt.jwt.verify_with_jwks` before ``from_params``, merging the
  JWT claims over the query parameters. RFC 8707 represents multiple
  ``resource`` values in a request object as a JSON array; expand that verified
  array into repeated ``("resource", value)`` pairs when building the ordered
  input to ``from_params``.
* ``put_with_ttl`` keeps the OP's view of the RP no longer than the trust
  anchor vouches for it. :class:`~pygrindvakt.client.InMemoryClientStore`
  supports it natively; a Python :class:`~pygrindvakt.client.ClientStoreProtocol`
  may implement ``put_with_ttl`` (a cache with expiry) or fall back to
  ``put``.
* Resolution happens on the authorization request, which is a browser
  round trip that can afford a few hundred milliseconds. Do not resolve at
  the token endpoint; by then the client must already be registered.
* Federation errors are :class:`pygrindvakt.GrindvaktError` subclasses whose
  messages describe which link of the chain failed. Log them; send the
  client a generic ``invalid_client``.

Serving your OP's entity configuration is the same
``build_entity_configuration`` call as for an RP, with ``openid_provider``
metadata built from ``op.discovery_document()`` plus
``client_registration_types_supported: ["automatic"]`` and the federation
members.
