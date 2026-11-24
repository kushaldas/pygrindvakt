pygrindvakt.client
==================

.. py:module:: pygrindvakt.client

Registered relying parties and the ``ClientStore`` protocol: the built-in
in-memory store, or any Python object with ``get(client_id)``, ``put(client)``
and optionally ``put_with_ttl(client, ttl_secs)``.

Constants
---------

The token-endpoint authentication methods, as used in
``Client.token_endpoint_auth_method`` and published in
``token_endpoint_auth_methods_supported``.

.. py:data:: AUTH_NONE
   :type: str
   :value: "none"

.. py:data:: AUTH_CLIENT_SECRET_BASIC
   :type: str
   :value: "client_secret_basic"

.. py:data:: AUTH_CLIENT_SECRET_POST
   :type: str
   :value: "client_secret_post"

.. py:data:: AUTH_PRIVATE_KEY_JWT
   :type: str
   :value: "private_key_jwt"

Client
------

.. py:class:: Client(client_id: str, *, client_secret: str | None = None, redirect_uris: list[str] | None = None, response_types: list[str] | None = None, grant_types: list[str] | None = None, token_endpoint_auth_method: str | None = None, jwks: dict[str, Any] | None = None, scope: str | None = None, subject_type: str | None = None, client_name: str | None = None)

   A registered relying party. Immutable.

   Every argument after ``client_id`` is keyword-only, and unknown keywords
   are a ``TypeError``, so a typo such as ``redirect_uri=`` (singular) cannot
   silently produce a client that never matches any redirect. This is a
   binding-level guard; grindvakt itself would accept and ignore the field.

   Defaults mirror grindvakt: ``response_types`` ``["code"]``,
   ``grant_types`` ``["authorization_code"]``,
   ``token_endpoint_auth_method`` ``"client_secret_basic"``, ``subject_type``
   ``"public"``. ``redirect_uris`` defaults to an empty list, which is fine
   for a ``client_credentials``-only client and useless for anything else.
   ``scope`` limits what a ``client_credentials`` client may request. ``jwks``
   is the client's public key set, required for ``private_key_jwt``.

   .. py:staticmethod:: from_dict(d: dict[str, Any]) -> Client

      Build from a dict in the same shape as :meth:`to_dict` (a JSON client
      registration). Unknown keys raise ``ValueError`` naming them; missing
      optional keys take the defaults above.

   .. py:method:: to_dict() -> dict[str, Any]

      The client as a dict, including ``client_secret`` if set.

   .. py:method:: registration_fingerprint() -> str

      Unpadded base64url SHA-256 of the registration snapshot. Credentials,
      keys and redirect URIs all contribute. Pass it as
      :attr:`AuthCodePayload.registration_digest
      <pygrindvakt.tokens.AuthCodePayload.registration_digest>` when your own
      code seals authorization codes. If the registration changes afterwards,
      redeeming the code fails with ``invalid_grant``.

      .. versionadded:: 0.6.0

   .. py:property:: client_id
      :type: str
   .. py:property:: client_secret
      :type: str | None
   .. py:property:: redirect_uris
      :type: list[str]
   .. py:property:: response_types
      :type: list[str]
   .. py:property:: grant_types
      :type: list[str]
   .. py:property:: token_endpoint_auth_method
      :type: str
   .. py:property:: jwks
      :type: dict[str, Any] | None

      The client's JWKS (for ``private_key_jwt`` and signed request objects)
      as a dict.

   .. py:property:: scope
      :type: str | None
   .. py:property:: subject_type
      :type: str
   .. py:property:: client_name
      :type: str | None

   .. py:method:: allows_redirect(uri: str) -> bool

      Whether ``uri`` **exactly** matches a registered redirect URI. There is
      no prefix or wildcard matching.

   .. py:method:: allows_response_type(rt: str) -> bool

      Whether the client is allowed the given response type.

   ``repr()`` shows the id, auth method, redirect URIs and grant types; never
   the secret.

   .. code-block:: python

      from pygrindvakt import client, keys

      web = client.Client(
          "demo",
          client_secret="s3cret",
          redirect_uris=["https://rp.example.com/cb"],
          grant_types=["authorization_code", "refresh_token"],
          client_name="Demo RP",
      )
      service = client.Client(
          "svc",
          client_secret="svc-secret",
          grant_types=["client_credentials"],
          token_endpoint_auth_method=client.AUTH_CLIENT_SECRET_POST,
          scope="read write",
      )
      rp_key = keys.signing_key_from_jwk(keys.generate_ec_jwk(), kid="rp-1")
      jwt_rp = client.Client(
          "jwt-rp",
          redirect_uris=["https://rp.example.com/cb"],
          token_endpoint_auth_method=client.AUTH_PRIVATE_KEY_JWT,
          jwks=rp_key.to_public_jwks(),
      )

Client store protocol
---------------------

.. py:class:: ClientStoreProtocol

   The duck-typed protocol accepted as the ``clients`` argument of
   :class:`pygrindvakt.provider.Provider`. A Django model manager, a cache, or
   a dict wrapper all qualify. The object is checked for callable ``get`` and
   ``put`` attributes when the ``Provider`` is built (``TypeError``
   otherwise).

   .. py:method:: get(client_id: str) -> Client | dict[str, Any] | None

      Return the registered client, or ``None`` if unknown. A dict in
      :meth:`Client.to_dict` shape is accepted and converted with
      :meth:`Client.from_dict`.

      **Fails closed:** if this raises, or returns something that is not a
      ``Client`` / valid dict / ``None``, the exception is logged through
      ``sys.unraisablehook`` and the lookup is treated as "unknown client",
      which the provider reports as ``invalid_client`` /
      ``unauthorized_client``.

   .. py:method:: put(client: Client) -> None

      Insert or replace a client with no expiry.

   .. py:method:: put_with_ttl(client: Client, ttl_secs: int) -> None

      *Optional.* Insert or replace a client that expires after ``ttl_secs``.
      Used by federation auto-registration (see :doc:`../guides/federation`).
      When the object has no ``put_with_ttl``, :meth:`put` is called instead,
      mirroring grindvakt's default.

   Exceptions in ``put`` / ``put_with_ttl`` are logged the same way and
   otherwise ignored. The methods run on the thread driving the provider
   call, holding the GIL. They may call back into pygrindvakt (for example
   delegate to an :class:`InMemoryClientStore`); such a nested call runs on
   a helper thread and costs one thread spawn.

   .. code-block:: python

      class DjangoClientStore:
          """Backs the OP's client registry with a Django model."""

          def get(self, client_id):
              try:
                  row = RegisteredClient.objects.get(pk=client_id)
              except RegisteredClient.DoesNotExist:
                  return None
              return row.as_dict()          # Client.to_dict() shape

          def put(self, client):
              RegisteredClient.objects.update_or_create(
                  pk=client.client_id, defaults={"data": client.to_dict()}
              )

Built-in store
--------------

.. py:class:: InMemoryClientStore(clients: list[Client | dict[str, Any]] | None = None)

   In-memory client store with optional per-entry TTL (used by federation
   auto-registration). Process-local: every worker process has its own copy,
   which is fine for a static client list and wrong for anything written at
   runtime.

   Seeding with duplicate ``client_id`` values raises ``ValueError``.
   grindvakt would silently keep the last entry; the binding refuses, because
   a duplicate in a configuration file is almost always a copy-paste error
   that would otherwise change which secret or redirect URI is live.

   .. py:method:: get(client_id: str) -> Client | None

      Look up a client. Expired TTL entries are removed on lookup.

   .. py:method:: put(client: Client | dict[str, Any]) -> None

      Insert or replace a client with no expiry. Dicts are accepted.

   .. py:method:: put_with_ttl(client: Client | dict[str, Any], ttl_secs: int) -> None

      Insert or replace a client that expires after ``ttl_secs`` seconds
      (``0`` expires immediately).

   .. code-block:: python

      store = client.InMemoryClientStore([web, service])
      store.put({"client_id": "late", "redirect_uris": ["https://late.example/cb"]})
      store.put_with_ttl(jwt_rp, 3600)
      store.get("demo").client_name        # "Demo RP"
      store.get("nobody")                  # None
