# Views and URLs

The five endpoints, and how to mount them for the default configuration
or for a custom *realm*. Source: `src/django_signet/views.py` and
`src/django_signet/urls.py`.

## The five endpoints

`include("django_signet.urls")` mounts these under names `login`,
`refresh`, `verify`, `logout` and `logout-all` (each route name equals
its path segment), in the `django_signet` namespace by default:

| URL name | View | Auth required | Reads |
|---|---|---|---|
| `login` | `TokenObtainView` | none | credentials in the request body |
| `refresh` | `TokenRefreshView` | none | the refresh credential |
| `verify` | `TokenVerifyView` | access token | the access credential |
| `logout` | `LogoutView` | none | the refresh credential |
| `logout-all` | `LogoutAllView` | none | the refresh credential |

`refresh`, `logout` and `logout-all` all act on the *refresh* credential,
not the access token - see `RefreshCredentialView`. That is also why they
need no `IsAuthenticated` permission of their own: presenting a valid
refresh credential *is* the authentication for these three. Their status
codes for a failed CSRF check and a bad credential differ on purpose;
see {doc}`exceptions`.

## Making verify a liveness check

`TokenVerifyView` is not strict by default. Its `BaseJWTAuthentication`
checks the access token's signature and expiry, not whether the session
is still live. An access token that outlives its session - a header
client's after logout, or any access token after logout-all from another
device or a reuse burn - keeps answering 200 until it expires. (A browser
logout clears the access cookie itself.) To have it confirm the session
too, list
a `Strict*` class in `authentication_classes`:

```python
from django.urls import include, path

from django_signet.authentication import StrictCookieJWTAuthentication
from django_signet.views import TokenVerifyView


class StrictTokenVerifyView(TokenVerifyView):
    authentication_classes = (StrictCookieJWTAuthentication,)


urlpatterns = [
    # Before the include, so it answers api/auth/verify instead.
    path("api/auth/verify", StrictTokenVerifyView.as_view()),
    path("api/auth/", include("django_signet.urls")),
]
```

`get_authenticators` binds every Signet class listed there to the view's
own transport, so the class chooses only the strictness: under a header
or hybrid realm, `StrictCookieJWTAuthentication` still reads the realm's
credential. Set it on a `TokenVerifyView` subclass, not on a realm: a
realm's attributes apply to all five endpoints.

## Realms: `signet_urls`

```{eval-rst}
.. autofunction:: django_signet.urls.signet_urls
```

A realm is a `SignetViewMixin` subclass - not the mixin itself - that
overrides `transport`, `rotation`, `get_claims()` or any other hook once,
for all five endpoints at once:

```python
class StaffRealm(SignetViewMixin):
    transport = HeaderTransport()


urlpatterns = [
    path("api/auth/", include("django_signet.urls")),
    path("staff/auth/", include(signet_urls(StaffRealm, namespace="staff"))),
]
```

Mount the result where the realm's refresh cookie path points - the
refresh cookie has to reach refresh, logout and logout-all, and system
check `signet.E008` fails startup when it cannot.

## Reference

```{eval-rst}
.. autoclass:: django_signet.views.SignetViewMixin
   :members:

.. autoclass:: django_signet.views.TokenObtainView

.. autoclass:: django_signet.views.RefreshCredentialView
   :members:

.. autoclass:: django_signet.views.TokenRefreshView

.. autoclass:: django_signet.views.TokenVerifyView
   :members:

.. autoclass:: django_signet.views.LogoutView

.. autoclass:: django_signet.views.LogoutAllView
```
