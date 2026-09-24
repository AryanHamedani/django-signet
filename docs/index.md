# django-signet

Polymorphic, secure-by-default JWT authentication for Django REST Framework.

Signet keeps both tokens in httpOnly cookies, out of reach of your
JavaScript, and handles the rest on the server: it rotates the refresh
token on every refresh, revokes the whole session when a spent refresh
token is presented again after a short grace window, checks a CSRF token
on every cookie-authenticated write, and keeps refresh tokens in its
token store only as SHA-256 digests.

It is for Django REST Framework projects whose API is called from a
browser, by a frontend on the same site. Mobile apps and other services
can sit beside it, on endpoints of their own that carry the tokens in the
`Authorization` header. It supports Python 3.12 or later, Django 5.2 or later, and Django
REST Framework 3.16 or later.

```{note}
The public API is not frozen until 1.0. Until then a minor release may
rename a hook or change its signature; every such change is listed in the
{doc}`changelog`.
```

## Install

```bash
pip install django-signet
```

Add `"rest_framework"` and `"django_signet"` to `INSTALLED_APPS`, mount
the endpoints with `path("api/auth/", include("django_signet.urls"))`, and
run `python manage.py migrate`.
The {doc}`tutorial/quickstart` does this step by step.

## The documentation

{doc}`tutorial/quickstart`
: Start here. Build a project where a browser logs in, calls a protected
  view, refreshes and logs out.

{doc}`howto/index`
: Solve one problem: a frontend on another subdomain, mobile clients, a
  second realm, custom claims, alerting on token theft, RS256 keys,
  purging expired sessions, choosing a store, deploying, migrating from
  Simple JWT.

{doc}`reference/index`
: Look up exact behaviour: every setting, system check, class, endpoint and
  signal.

{doc}`explanation/index`
: Understand the design: the security model, the architecture, the
  limitations, and how Signet compares with Simple JWT.

Source code: <https://github.com/AryanHamedani/django-signet>

```{toctree}
:hidden:
:maxdepth: 2

tutorial/quickstart
howto/index
reference/index
explanation/index
```

```{toctree}
:hidden:
:caption: Project

changelog
contributing
security
code-of-conduct
```
