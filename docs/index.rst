pygrindvakt
===========

**pygrindvakt** is a Python binding for `grindvakt
<https://github.com/kushaldas/grindvakt>`_ 0.12.x, a runtime-agnostic Rust
library for **OAuth 2.0**, **OpenID Connect** and **OpenID Federation 1.1**. It
exposes grindvakt's OpenID Provider engine, its Relying Party toolkit,
federation trust-chain resolution, DPoP (RFC 9449) proof validation, and the
JOSE / key primitives underneath to Python, including PKCS#11 (HSM) signing.

.. important::

   OAuth 2.0 and OpenID Connect are security protocols, and this binding hands
   attacker-controlled request parameters, tokens and JWTs straight into
   authentication decisions. Before integrating, read the
   :doc:`security guide <guides/security>`: it covers the fail-closed guards
   the binding adds on top of grindvakt, the ``unsafe_*`` escape hatches, why
   ``token_url`` must come from configuration and never from the ``Host``
   header, and why ``str(exc)`` must never be sent to a client.

What the binding adds
---------------------

grindvakt itself is a library of ``async`` Rust functions and traits. The
binding turns that into something a Python web application can call directly:

* **A synchronous API over an embedded tokio runtime.** Every networked or
  store-backed call is driven to completion on a process-wide runtime with the
  GIL released, so threads run in parallel. The runtime and the built-in HTTP client are
  PID-aware and rebuild themselves after a quiescent ``fork`` (gunicorn,
  uwsgi, ``multiprocessing``). Store objects are the exception: a
  ``RedisStore`` is process-bound and fails closed in a forked child, so
  build it, and any ``Provider`` that uses it, in each worker. See
  :doc:`guides/stores`.
* **Framework agnosticism.** Requests come in as plain dicts and strings,
  responses go out as a :class:`pygrindvakt.http.Response` (``status``,
  ``headers``, ``body``). The same :class:`pygrindvakt.provider.Provider`
  works under Flask, Django, FastAPI, or anything else; the framework adapters
  are a few lines each (:doc:`guides/op_flask`, :doc:`guides/op_django`,
  :doc:`guides/op_fastapi`).
* **Python protocol adapters.** The client store, token-use store, DPoP replay
  store and outbound HTTP client can each be a built-in class *or* any Python
  object implementing a small duck-typed protocol (Django ORM, redis-py, an
  ``httpx`` client with custom CAs). Adapters **fail closed**: a Python
  exception is logged through ``sys.unraisablehook`` and reported to the
  client as ``server_error``, never as a silent pass.
* **Fail-closed hardening beyond upstream.** The binding refuses several
  things grindvakt silently accepts: an id_token verified without a nonce,
  duplicate client ids, unknown ``Client`` fields, reserved id_token claims in
  ``extra_claims``, outbound redirects, a per-call ``redirect_uri`` override
  that is not registered on the :class:`pygrindvakt.rp.RpClient`, a
  ``post_logout_redirect_uri`` that is not registered, and a non-https or
  malformed endpoint URL in a provider metadata document. Most guards are
  escapable only through an explicit ``unsafe_*`` argument that emits a
  ``UserWarning``; the redirect-registration check is escaped with
  ``allow_unregistered_redirect_uri=True``, which is set at construction and
  shows up in ``repr()`` but warns nothing.

The binding mirrors grindvakt's modules as Python submodules:

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Submodule
     - Purpose
   * - :doc:`pygrindvakt.http <api/http>`
     - Framework-agnostic request / response types, the ``HttpClient``
       protocol, and the built-in reqwest client.
   * - :doc:`pygrindvakt.keys <api/keys>`
     - Signing keys from PEM / DER, JWK, or a PKCS#11 token; JWK generation
       and thumbprints.
   * - :doc:`pygrindvakt.client <api/client>`
     - Registered relying parties and the ``ClientStore`` protocol.
   * - :doc:`pygrindvakt.metadata <api/metadata>`
     - The OpenID Provider discovery document.
   * - :doc:`pygrindvakt.request <api/request>`
     - Parsed OIDC authorization requests.
   * - :doc:`pygrindvakt.tokens <api/tokens>`
     - The stateless token codec and its sealed payloads.
   * - :doc:`pygrindvakt.provider <api/provider>`
     - The OpenID Provider engine and the ``TokenUseStore`` protocol.
   * - :doc:`pygrindvakt.dpop <api/dpop>`
     - RFC 9449 DPoP proof validation and the ``ReplayStore`` protocol.
   * - :doc:`pygrindvakt.rp <api/rp>`
     - The Relying Party side: discovery, code exchange, id_token
       verification, userinfo, client assertions.
   * - :doc:`pygrindvakt.federation <api/federation>`
     - OpenID Federation entity statements, trust-chain resolution, signed
       JWKS, collections, metadata policy.
   * - :doc:`pygrindvakt.discovery <api/discovery>`
     - Home-organization discovery and Third-Party Initiated Login.
   * - :doc:`pygrindvakt.jwt <api/jwt>`
     - Thin JWS sign / verify helpers.
   * - :doc:`pygrindvakt.pkce <api/pkce>`
     - RFC 7636 PKCE helpers.
   * - :doc:`pygrindvakt.mac <api/mac>`
     - HMAC-SHA256, SHA-256, constant-time comparison.
   * - :doc:`pygrindvakt.util <api/util>`
     - Time and randomness helpers.

Design in one sentence: JSON-shaped values (claims, JWKs, metadata) cross the
boundary as native Python dicts and lists, wrapped Rust objects are immutable
handles you can share freely across threads, and private key material never
crosses into Python at all.

.. toctree::
   :maxdepth: 2
   :caption: Getting started

   installation
   quickstart

.. toctree::
   :maxdepth: 2
   :caption: Guides

   guides/security
   guides/op_flask
   guides/op_django
   guides/op_fastapi
   guides/rp
   guides/federation
   guides/dpop
   guides/stores

.. toctree::
   :maxdepth: 2
   :caption: API reference

   api/index

.. toctree::
   :maxdepth: 1
   :caption: Reference

   exceptions

Release notes
-------------

The `CHANGELOG
<https://github.com/kushaldas/pygrindvakt/blob/main/CHANGELOG.md>`_ is the
release-by-release record, and the only place where breaking changes between
releases are listed in full; it is not mirrored into this manual. The table
below maps each binding release to the protocol engine it binds (the same
version is what ``Cargo.lock`` pins).

.. list-table::
   :header-rows: 1
   :widths: 30 30 40

   * - pygrindvakt
     - grindvakt
     - Notes
   * - 0.4.1
     - 0.11.0
     - binds core 0.11 (Rust 1.89), a dependency-only release: stable ``rsa`` 0.10.0
       (RUSTSEC-2023-0071 fixed), ``jose-rs`` 0.11.0, ``kryptering`` 0.7.1; locked
       and pinned wheel build, ``cargo audit`` and ``pip-audit`` in CI.
   * - 0.4.0
     - 0.10.0
     - binds core 0.10 (Rust 1.89): RFC 9207 ``iss`` for the in-process ``Provider``,
       header and ``Location`` injection checks on ``http.Response``, stricter
       ``redirect_uri`` rules on authorization redirects, quiet and stricter test suite.
   * - 0.3.0
     - 0.9.1
     - fail-closed RP hardening: ``ConfigError``/``BadRequestError``, authorization
       response parsing, ``DiscoveryCache``, ``pygrindvakt.testing``.
   * - 0.2.0
     - 0.9.0
     - id_token hash binding (``strict_hashes``), registered redirect and
       post-logout redirect URIs, metadata URL validation.
   * - 0.1.0
     - 0.8.0
     - initial binding with fail-closed OIDC validation.

Architecture decision records
-----------------------------

The design decisions behind the binding are recorded as Markdown ADRs in the
repository rather than in this manual:

* `ADR 0001 <https://github.com/kushaldas/pygrindvakt/blob/main/docs/adr/0001-sync-api-over-embedded-tokio-runtime.md>`_:
  synchronous Python API over an embedded, PID-keyed tokio runtime.
* `ADR 0002 <https://github.com/kushaldas/pygrindvakt/blob/main/docs/adr/0002-python-protocol-adapters.md>`_:
  Python protocol adapters for stores and outbound HTTP, failing closed.
* `ADR 0003 <https://github.com/kushaldas/pygrindvakt/blob/main/docs/adr/0003-fail-closed-hardening.md>`_:
  fail-closed hardening added at the binding boundary.
* `ADR 0004 <https://github.com/kushaldas/pygrindvakt/blob/main/docs/adr/0004-redirect-registration-and-hash-binding.md>`_:
  redirect registration and opt-in id_token hash binding (0.2.0).
* `ADR 0005 <https://github.com/kushaldas/pygrindvakt/blob/main/docs/adr/0005-error-layout.md>`_:
  error layout: `BadRequestError` and `ConfigError` are also `ValueError`s; `auth_failure`, `retryable`, `log_summary` (0.3.0).
* `ADR 0006 <https://github.com/kushaldas/pygrindvakt/blob/main/docs/adr/0006-shared-secret-algorithms-and-published-jwks.md>`_:
  `HS*` ID tokens use a key set built from the `client_secret`; published JWKS never supply shared secrets (0.3.0).
* `ADR 0007 <https://github.com/kushaldas/pygrindvakt/blob/main/docs/adr/0007-authorization-response-parsing.md>`_:
  authorization response parsing: fail-closed callback parse, no raw `error_description`, `iss` compared by the caller (0.3.0).
* `ADR 0008 <https://github.com/kushaldas/pygrindvakt/blob/main/docs/adr/0008-discovery-cache.md>`_:
  discovery cache: `rp.DiscoveryCache` with single flight, failure back-off and bounded stale metadata; keys never stale (0.3.0).

The full list lives in the `docs/adr
<https://github.com/kushaldas/pygrindvakt/tree/main/docs/adr>`_ directory.

Indices
-------

* :ref:`genindex`
* :ref:`search`
