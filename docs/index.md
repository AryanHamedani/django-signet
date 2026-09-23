# django-signet

Polymorphic, secure-by-default JWT authentication for Django REST Framework.

Authentication stays entirely in the backend: tokens travel in httpOnly
cookies, rotate on every refresh, and never appear in a response body or in
JavaScript.

Source code: <https://github.com/AryanHamedani/django-signet>

```{toctree}
:maxdepth: 2

tutorial/quickstart
howto/index
reference/index
stores
migrating-from-simplejwt
```
