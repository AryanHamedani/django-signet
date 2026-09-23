# Transports

A transport moves tokens between the library and the wire - reading them
off a request, writing them onto a response - and knows nothing about
storage or authentication. Source: `src/django_signet/transport/`.

Three implementations:

- **`CookieTransport`** - `Secure`/`HttpOnly` cookies. Ambient: the
  browser attaches them to every matching request on its own, which is
  exactly what makes CSRF possible and exactly why `CookiePolicy` exists.
- **`HeaderTransport`** - `Authorization: Bearer <token>`. Never ambient
  and never subject to CSRF, for mobile and service-to-service clients.
- **`HybridTransport`** - reads either (cookie first, header fallback),
  but only ever *writes* cookies. Not a transport for mobile clients -
  see its docstring below for why.

`Transport.is_ambient` is what the CSRF check keys off, and
`Transport.cookie_policy` is how any code that needs one (CSRF issuance
and validation, the `signet.E008` system check) asks for it
polymorphically instead of assuming every transport has one.

## Cookie naming and flags

`CookiePolicy` resolves every cookie-related setting - see
{doc}`settings` for the full list of `COOKIE_*` keys and the
`__Host-`/`__Secure-` prefix rules it applies.

```{eval-rst}
.. autoclass:: django_signet.transport.cookie.CookiePolicy
   :members:
```

## Reference

```{eval-rst}
.. autoclass:: django_signet.transport.base.Transport
   :members:

.. autoclass:: django_signet.transport.cookie.CookieTransport
   :members:

.. autoclass:: django_signet.transport.header.HeaderTransport
   :members:

.. autoclass:: django_signet.transport.header.HybridTransport
   :members:
```
