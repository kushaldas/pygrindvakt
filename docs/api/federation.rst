pygrindvakt.federation
======================

.. py:module:: pygrindvakt.federation

OpenID Federation 1.1 support: entity statements (build and verify),
trust-chain resolution by delegating to a trust anchor's
``federation_resolve_endpoint``, signed-JWKS fetching, the collection
(listing) endpoint used for OP discovery pages, and the metadata-policy
operators. :doc:`../guides/federation` puts them together, including OP-side
automatic client registration.

JSON-shaped values (claims, JWKS, metadata, policies) cross the boundary as
native Python dicts and lists. Networked functions take an ``http`` client as
their first positional argument (``None`` selects the built-in client) and
block the calling thread with the GIL released.

Constants
---------

The ``typ`` header values the federation JWTs must carry.

.. py:data:: ENTITY_STATEMENT_TYP
   :type: str
   :value: "entity-statement+jwt"

.. py:data:: RESOLVE_RESPONSE_TYP
   :type: str
   :value: "resolve-response+jwt"

.. py:data:: JWK_SET_TYP
   :type: str
   :value: "jwk-set+jwt"

.. py:data:: TRUST_MARK_TYP
   :type: str
   :value: "trust-mark+jwt"

   .. versionadded:: 0.7.0

Classes
-------

.. py:class:: EntityStatement

   The decoded claims of an entity statement: an entity configuration, a
   subordinate statement or a resolve response. Immutable. Returned by the
   ``verify*`` functions and by :func:`decode_unverified`.

   .. py:property:: claims
      :type: dict[str, Any]

      All claims of the statement as a dict.

   .. py:method:: iss() -> str | None

      The ``iss`` claim, if present.

   .. py:method:: sub() -> str | None

      The ``sub`` claim, if present.

   .. py:method:: jwks() -> dict[str, Any]

      The ``jwks`` carried in the statement (the subject's federation keys)
      as a ``{"keys": [...]}`` dict. Raises
      :class:`pygrindvakt.BadRequestError` if absent. Symmetric (``oct``)
      keys are dropped with a ``UserWarning``: federation entities sign with
      asymmetric keys; symmetric keys cannot be published.

      .. versionchanged:: 0.3.0
         ``oct`` keys are dropped with a ``UserWarning``.

   .. py:method:: metadata(kind: str) -> dict[str, Any] | None

      A metadata sub-document, e.g. ``metadata("openid_provider")``, or
      ``None``.

   .. py:method:: authority_hints() -> list[str]

      The ``authority_hints`` list (empty if absent).

.. py:class:: ResolvedEntity

   A successful resolve response, bound to a configured trust anchor.
   Immutable. Returned by :func:`resolve_via_trust_anchors`.

   .. py:property:: issuer
      :type: str

      The trust anchor that issued the resolve response.

   .. py:property:: subject
      :type: str

      The resolved entity id.

   .. py:property:: metadata
      :type: dict[str, Any]

      The resolved (policy-applied) ``metadata`` object as a dict, keyed by
      entity type (``openid_relying_party``, ``openid_provider``,
      ``federation_entity``, ...).

   .. py:property:: subject_jwks
      :type: dict[str, Any]

      The subject's federation signing keys from the entity configuration
      at the start of the returned trust chain, as a ``{"keys": [...]}``
      dict. Symmetric (``oct``) keys are dropped with a ``UserWarning``
      (federation entities sign with asymmetric keys), so the set is safe to
      pass on to :func:`entity_metadata_jwks`.

      .. versionchanged:: 0.3.0
         ``oct`` keys are dropped with a ``UserWarning``.

   .. py:property:: exp
      :type: int | None

      Expiry (seconds since epoch) of the resolved result: the earlier of
      the resolve response's ``exp`` and the earliest expiry in its
      validated trust chain. Use it to bound caching.

      .. versionchanged:: 0.6.0
         Bounded by the trust chain's expiries, not only the resolve
         response's ``exp``.

   .. py:property:: trust_marks
      :type: list[Any]

      The raw ``trust_marks`` entries from the trust anchor's signed resolve
      response (empty if absent). They are **not verified**: pass them to
      :func:`verify_trust_marks` before trusting any entry.

      .. versionadded:: 0.6.0

.. py:class:: CollectionEntity(*, entity_id: str, display_name: str, logo_uri: str | None = None)

   One entity returned by a trust anchor's collection (listing) endpoint,
   with its UI presentation flattened for a discovery page. Immutable and
   comparable with ``==``.

   .. py:property:: entity_id
      :type: str

      The entity identifier (the OP to authenticate against).

   .. py:property:: display_name
      :type: str

      A human-friendly name: the entity-type display name, else the
      ``federation_entity`` display name, else the entity id. Treat it as
      untrusted text and HTML-escape it when rendering.

   .. py:property:: logo_uri
      :type: str | None

      An optional logo URL for the discovery page. Not scheme-checked;
      allow only ``https`` before emitting it as an ``<img src>``.

Entity statements: build, decode, verify
----------------------------------------

.. py:function:: build_entity_configuration(key: SigningKey, entity_id: str, public_jwks: dict[str, Any], authority_hints: list[str], metadata: dict[str, Any], trust_marks: list[dict[str, Any]] | None = None, lifetime: int = 3600) -> str

   Build and sign a self-issued Entity Configuration JWT
   (``iss == sub == entity_id``, ``typ = entity-statement+jwt``, ``iat`` /
   ``exp`` set from ``lifetime`` seconds).

   ``public_jwks`` is the ``{"keys": [...]}`` dict to publish (normally
   ``key.to_public_jwks()``), ``metadata`` the per-entity-type metadata
   object, ``trust_marks`` an optional list of trust mark objects. Serve the
   result at ``<entity_id>/.well-known/openid-federation`` with content type
   ``application/entity-statement+jwt``.

   A symmetric (``oct``) key in ``public_jwks`` emits a ``UserWarning``
   ("federation.build_entity_configuration() is publishing a symmetric (oct)
   key") and is still included: the call does not filter what you configured,
   but federation verifiers drop ``oct`` keys, so the statement is not
   verifiable by them against that key. Only ``public_jwks`` is checked
   (``SigningKey.to_public_jwks()`` of an ``HS*`` key yields an ``oct`` entry
   without ``k``).

   .. versionchanged:: 0.3.0
      Warns when ``public_jwks`` contains an ``oct`` key.

   .. code-block:: python

      ec = federation.build_entity_configuration(
          fed_key, "https://rp.example.com", fed_key.to_public_jwks(), ["https://ta.example.org"],
          {"openid_relying_party": {"client_name": "RP", "redirect_uris": ["https://rp.example.com/cb"],
                                    "jwks": client_key.to_public_jwks(),
                                    "token_endpoint_auth_method": "private_key_jwt"}},
          lifetime=86400,
      )

.. py:function:: decode_unverified(token: str) -> EntityStatement

   Decode an entity statement **without** verifying its signature.

   .. warning::

      Inspection only, for example reading ``authority_hints`` to learn
      whom to ask. Never trust these claims.

.. py:function:: verify(token: str, jwks: dict[str, Any]) -> EntityStatement

   Verify an entity statement's signature against a JWKS dict and require
   ``typ = entity-statement+jwt`` and a present ``exp``. Use it for
   subordinate statements, with the issuer's federation keys.

   A token whose header ``alg`` is ``HS256``, ``HS384``, ``HS512`` or
   ``none`` is refused with :class:`pygrindvakt.AuthnError`
   (``code == "symmetric_algorithm"``) before any key is consulted, and any
   ``oct`` key in ``jwks`` is dropped with a ``UserWarning``. Federation
   entities sign with asymmetric keys; symmetric keys cannot be published.

   .. versionchanged:: 0.3.0
      MAC-signed and unsigned statements are refused; ``oct`` keys are
      dropped from ``jwks``.

.. py:function:: verify_typed(token: str, jwks: dict[str, Any], typ: str) -> EntityStatement

   Verify a trust-anchor-signed JWT against a JWKS dict, requiring the given
   ``typ`` header (e.g. :data:`RESOLVE_RESPONSE_TYP`) and a present ``exp``.
   A statement with the wrong ``typ`` is rejected even if the signature is
   valid. The same ``alg`` refusal and ``oct`` drop as :func:`verify`
   apply.

.. py:function:: verify_self_signed(token: str) -> EntityStatement

   Verify a self-issued Entity Configuration using the keys it carries:
   ``iss`` must equal ``sub`` and the signature must validate against the
   embedded ``jwks``. A statement issued by someone else, or without
   ``jwks``, is rejected. A token signed with ``HS256`` / ``HS384`` /
   ``HS512`` or ``none`` is refused with ``AuthnError``
   (``code == "symmetric_algorithm"``), as in :func:`verify`.

.. py:function:: verify_trust_marks(marks: list[Any], issuer_jwks: dict[str, Any], required_type: str, *, subject: str, issuer: str | None = None, require_exp: bool = True) -> list[EntityStatement]

   Verify the trust marks of ``required_type`` among ``marks`` (typically
   :attr:`ResolvedEntity.trust_marks`) and return every one that verifies.
   Core only stores trust marks raw; this verification is implemented in the
   binding.

   ``issuer_jwks`` must be the verified keys of the trust MARK ISSUER. That
   equals the trust anchor only when the anchor issues the mark itself; a
   mark issued by another entity needs that entity's own (verified) keys.
   ``oct`` keys are dropped with a ``UserWarning``.

   Entries whose ``trust_mark_type`` is not ``required_type``, and entries
   that are not dicts, are ignored. Each remaining entry's ``trust_mark`` JWT
   must have ``typ`` ``trust-mark+jwt``, ``sub == subject``, ``iss == issuer``
   (when given), a valid signature, valid ``exp`` / ``nbf`` / ``iat`` (60 s
   leeway), an inner ``trust_mark_type`` equal to ``required_type`` and an
   ``iss``. A ``delegation`` claim fails closed (delegation owner keys are
   not supported). Entries that fail are skipped.

   ``exp`` is optional in the specification. ``require_exp=True`` (default)
   is a deliberate fail-closed deviation that rejects marks without ``exp``;
   pass ``False`` to accept them.

   :raises AuthnError: ``code == "trust_mark_missing"`` if no entry of
      ``required_type`` exists; ``"trust_mark_invalid"`` if entries exist but
      none verifies; ``"symmetric_algorithm"`` if an entry's ``alg`` is
      ``HS*`` or ``none`` (raised at once).

   .. versionadded:: 0.7.0

Networked: fetch, resolve, keys, collection
-------------------------------------------

.. py:function:: fetch_entity_configuration(http: HttpClientProtocol | None, entity_id: str) -> str

   Fetch an entity's configuration JWT from
   ``<entity_id>/.well-known/openid-federation`` (a trailing slash on the
   entity id is handled). Returns the raw compact JWS, unverified; pass it
   to :func:`verify_self_signed`. A non-200 raises
   :class:`pygrindvakt.InternalError`.

.. py:function:: resolve_via_trust_anchors(http: HttpClientProtocol | None, sub: str, trust_anchors: dict[str, dict[str, Any]]) -> ResolvedEntity

   Resolve ``sub``'s metadata by delegating to each configured trust
   anchor's ``federation_resolve_endpoint`` (OpenID Federation section 10).

   ``trust_anchors`` maps trust anchor entity id to its trusted JWKS dict
   (``{"keys": [...]}``, pinned in configuration; a non-JWKS value raises).
   For each anchor, the anchor's own entity configuration is fetched and
   verified against those keys, then
   ``<federation_resolve_endpoint>?sub=...&trust_anchor=...`` is called; the
   resolve response (``typ = resolve-response+jwt``, signed by the anchor)
   and the ``trust_chain`` it carries are fully validated: the chain starts
   with ``sub``'s entity configuration, ends at the anchor, every
   subordinate statement is signed by the entity above it, and the response
   ``sub`` matches. The first anchor that succeeds wins; otherwise the last
   error is raised (:class:`pygrindvakt.AuthnError` for a chain that does
   not validate, :class:`pygrindvakt.InternalError` for transport failures,
   :class:`pygrindvakt.ConfigError` when ``trust_anchors`` is empty).

   Any ``oct`` (symmetric) key in a ``trust_anchors`` JWKS is dropped with a
   ``UserWarning`` before use, so a trust anchor cannot be verified with a
   shared secret.

   .. versionchanged:: 0.3.0
      ``oct`` keys in ``trust_anchors`` are dropped with a ``UserWarning``.

   .. code-block:: python

      TRUST_ANCHORS = {"https://ta.example.org": json.load(open("ta.jwks.json"))}
      entity = federation.resolve_via_trust_anchors(None, "https://op.example.edu", TRUST_ANCHORS)
      op_meta = entity.metadata["openid_provider"]
      cache_for = entity.exp - util.now_secs()

.. py:function:: entity_metadata_jwks(http: HttpClientProtocol | None, metadata: dict[str, Any], subject_entity_id: str, subject_fed_jwks: dict[str, Any]) -> dict[str, Any]

   Resolve an entity type's key set from its metadata (OpenID Federation
   1.1 section 5.2.1): inline ``jwks``, else ``signed_jwks_uri`` (fetched
   and verified against ``subject_fed_jwks`` with :func:`fetch_signed_jwks`),
   else plain ``jwks_uri``. A malformed inline ``jwks`` is an error, not a
   fallback. Returns a ``{"keys": [...]}`` dict. ``metadata`` is one entity
   type's object, e.g. ``entity.metadata["openid_provider"]``.

   ``subject_fed_jwks`` is the verifier key set for ``signed_jwks_uri``. Any
   ``oct`` key in it is dropped with a ``UserWarning`` before verification,
   so a symmetric-keyed (``HS*``) signed JWK Set is never accepted: federation
   entities sign with asymmetric keys, and symmetric keys cannot be published.

   Published key sets must not carry symmetric keys (OIDC Core 10.1). Every
   ``oct`` key in the returned set is dropped, whether it came from inline
   ``jwks``, ``signed_jwks_uri`` or ``jwks_uri``, and a ``UserWarning``
   ("published JWKS contains a symmetric (oct) key, ignored") is emitted. The
   drop is unconditional: a warning filter can hide the warning, and one that
   turns it into an error has the error discarded, but the key is dropped
   either way.

   .. versionchanged:: 0.3.0
      ``oct`` keys are dropped with a ``UserWarning``, from the result and
      from ``subject_fed_jwks``.

.. py:function:: fetch_signed_jwks(http: HttpClientProtocol | None, signed_jwks_uri: str, subject_entity_id: str, subject_fed_jwks: dict[str, Any]) -> dict[str, Any]

   Fetch and verify a signed JWK Set document (``typ = jwk-set+jwt``) from
   ``signed_jwks_uri``. The signature must validate against
   ``subject_fed_jwks`` and the ``sub`` must equal ``subject_entity_id``.
   Returns a ``{"keys": [...]}`` dict. Every ``oct`` (symmetric) key is
   dropped from the result with a ``UserWarning``, as in
   :func:`entity_metadata_jwks`. Any ``oct`` key in ``subject_fed_jwks`` is
   dropped as well, before verification, so a document signed with
   ``HS256`` / ``HS384`` / ``HS512`` fails verification.

   .. versionchanged:: 0.3.0
      ``oct`` keys are dropped with a ``UserWarning``, from the result and
      from ``subject_fed_jwks``.

.. py:function:: fetch_collection(http: HttpClientProtocol | None, collection_endpoint: str, entity_type: str) -> list[CollectionEntity]

   Fetch the entities of ``entity_type`` (e.g. ``"openid_provider"``) from a
   trust anchor's collection endpoint (``<endpoint>?entity_type=...``) and
   flatten their UI info for a discovery page.

.. py:function:: parse_collection(body: dict[str, Any], entity_type: str) -> list[CollectionEntity]

   Parse a collection-endpoint response body
   (``{"entities": [{"entity_id": ..., "entity_types": [...], "ui_infos": {...}}]}``)
   into :class:`CollectionEntity` objects. Entries without an ``entity_id``,
   or that do not advertise ``entity_type`` in ``entity_types``, are
   skipped. The display name is taken from the entity type's ``ui_infos``,
   falling back to ``federation_entity`` and then to the entity id.

   .. code-block:: python

      ops = federation.fetch_collection(None, "https://ta.example.org/collection", "openid_provider")
      choices = [(e.entity_id, e.display_name, e.logo_uri) for e in ops]

Metadata policy
---------------

.. py:function:: apply_policy(metadata: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]

   Apply a metadata policy (OpenID Federation section 6) to a metadata
   object and return the resulting dict; the input is not modified.

   Supports the ``value``, ``default``, ``add``, ``one_of``, ``subset_of``,
   ``superset_of`` and ``essential`` operators. Raises
   :class:`pygrindvakt.AuthnError` when the metadata violates a constraint
   and :class:`pygrindvakt.BadRequestError` for a malformed policy.

   .. code-block:: python

      out = federation.apply_policy(
          {"scope": ["openid", "email", "profile"]},
          {"scope": {"subset_of": ["openid", "email"]}, "response_types": {"default": ["code"]}},
      )
      # {"scope": ["openid", "email"], "response_types": ["code"]}
