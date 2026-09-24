# Run a second realm beside the default one

A *realm* is one `SignetViewMixin` subclass. Its transport, rotation policy
and hooks are declared once, and `signet_urls()` turns it into the five
endpoints, all of which use them. This guide adds a staff realm with cookies
of its own beside the default endpoints, and a view only staff can use.

It then sets out what a realm does and does not keep apart. The short
version: **a realm is not an authorization boundary by itself.** It decides
which credential its endpoints and views read. A permission class decides who
gets in.

Realms, `signet_urls()` and every hook named here are public API, but the
API is not frozen until 1.0; see
[Pin the version](deploying.md#pin-the-version).

## Declare the realm

```{literalinclude} ../examples/realms_urls.py
:language: python
:start-at: from django.urls
```

`CookiePolicy(prefix="staff", refresh_path="/staff/auth/")` names the
realm's cookies `__Host-staff-access`, `__Secure-staff-refresh` and
`__Host-staff-csrf`. The refresh cookie's path is `/staff/auth/`, where the
realm is mounted. The access and CSRF cookies are set at `/`, like the
default realm's.

Every `CookiePolicy` field you do not pass follows the
[cookie settings](../reference/settings.md#cookie-settings), as the default
cookies do: `"COOKIE_SECURE": False` in local settings drops the prefixes
from both realms' names. The exception to watch for is an explicit name.
[`COOKIE_ACCESS_NAME`](../reference/settings.md#cookie_access_name) and its
two siblings are used verbatim by every policy that does not pass its own,
so setting one gives both realms the same cookie. If you set them, pass the
realm's own names to its policy as `explicit_access_name`,
`explicit_refresh_name` and `explicit_csrf_name`.

`StaffCookieAuthentication` uses the same transport object as the realm, so
your staff views read the cookies the staff endpoints set. The stock
`CookieJWTAuthentication` reads the default names and never sees them.

`namespace="staff"` names the endpoints `staff:login`, `staff:refresh`,
`staff:verify`, `staff:logout` and `staff:logout-all`.

## Mount the realm under its refresh path

The refresh cookie reaches only URLs under its path, so the realm must be
mounted there. `signet.E008` checks each realm against its own
`CookiePolicy`: it walks your URLconf and reads the policy of every mounted
refresh, logout and logout-all view. Mount `StaffRealm` anywhere outside
`/staff/auth/` and `manage.py check` reports all three of its views. See
[`signet.E008`](../reference/checks.md#signete008---refresh-credential-endpoint-outside-the-cookies-path).

The staff view is mounted at `/staff/api/reports`, outside `/staff/auth/`,
so the refresh cookie is not sent to it. See
[Mount nothing else under the refresh path](deploying.md#mount-nothing-else-under-the-refresh-path).

## Log in and send the CSRF header

Post the credentials as JSON to `/staff/auth/login`. The response sets the
three staff cookies. Refresh with `POST /staff/auth/refresh`, sending the
`X-CSRF-Token` header as with the default realm.

Each realm checks the header against its own CSRF cookie. A browser signed
in to both realms holds two, `__Host-signet-csrf` and `__Host-staff-csrf`.
Refresh, logout and logout-all at the staff realm, and unsafe requests to
views that use `StaffCookieAuthentication`, must carry the value of
`__Host-staff-csrf`. The other value answers 403. Login needs no CSRF header
at either realm.

## Pair the realm with a permission class

`StaffReportView` lists `IsAdminUser`, and that is what keeps other users
out. Nothing about the realm does:

- The staff login checks the password and that the account is active, as
  the default login does. It does not check `is_staff`. Any user can log in
  at `/staff/auth/login` and get staff-realm cookies.
- `IsAdminUser` checks `request.user.is_staff`. The authentication classes
  load `request.user` from the database on every request, so a user you
  demote is refused on their next request, while their access token is
  still valid.

Put a permission class on every view that needs one. If the same test
applies to every view of a realm, a subclass of DRF's `BasePermission` keeps
it in one place.

## What does and does not keep realms apart

A token carries no record of the realm that issued it. Its claims are the
reserved ones and whatever `get_claims()` returned (see
{doc}`custom-claims`). Here is what each mechanism does.

| Mechanism | Keeps realms apart? |
|---|---|
| Signing key | No. `ALGORITHM`, `SIGNING_KEY` and `VERIFYING_KEY` are project settings. Every realm signs and verifies with the same key. |
| `AUDIENCE` | No. It is one setting, so every realm mints and checks the same `aud`. |
| Cookie names | Only for what a browser sends. Each authentication class reads the name its transport's policy gives it. A token copied into the other realm's cookie authenticates there, and anyone can set cookies in their own browser. |
| Cookie paths | Only for the refresh cookie. The access and CSRF cookies of every realm are set at `/` and reach every URL. |
| The token store | No. There is one store, `SIGNET["STORE"]`. A refresh token from any realm, presented through another realm's transport, redeems at that realm's refresh endpoint. |
| Header transport | No. `HeaderTransport` reads `Authorization: Bearer` unless you pass another `header` or `keyword`, so `HeaderJWTAuthentication` accepts an access token from any realm, cookie realms included. Another header or keyword is naming, like cookie names. |

The store row has consequences worth spelling out:

- **A session opened at one realm can be refreshed at another.** The
  successor comes back through the refreshing realm's transport, with the
  claims its `get_claims()` returns. So a claim such as `{"realm": "staff"}`
  does not, on its own, record where a session began, and restricting who
  can log in at a realm, with its own `serializer_class`, does not restrict
  who ends up holding its tokens. The next section closes this.
- **Revocation spans every realm.** Logout-all at any realm, and a password
  change, revoke every session of the user, whichever realm opened it. (A
  store that cannot revoke by user revokes none; see
  {doc}`choosing-a-store`.)

What stops a user getting into a view is the permission class on that view,
checked against the user as they are now.

## Bind a session to its realm

A permission class answers *who* the user is. It cannot tell *how* the
session began. If the staff realm's login is stricter than the default one,
with its own `serializer_class` requiring a second factor say, a session
opened at the default login can still be refreshed at the staff realm and
come back with staff cookies.

To close that, have the realm stamp its tokens with a claim, and refuse any
token without it, both at refresh and in the realm's views:

```{literalinclude} ../examples/realm_binding_urls.py
:language: python
:start-at: from django.urls
```

- `get_claims` puts `{"realm": "staff"}` in both tokens, at login and at
  every refresh at this realm.
- `StaffRotationPolicy.get_user` sees the refresh token's claims before it
  is consumed, and raises a `SignetError` for a token without the claim.
  A default-realm refresh token presented at `staff:refresh` gets 401.
- `StaffCookieAuthentication.validate_claims` does the same for access
  tokens, so a default-realm access token copied into the staff cookie gets
  401 at the staff views.

The pattern has three limits:

- **A refused refresh burns the session it presented.** Refusing in
  `get_user` revokes that session with the reason `admin`, as for a
  disabled account: the default-realm session whose refresh token was
  carried to `staff:refresh` ends.
- **`staff:verify` still accepts any realm's token.** The verify endpoint
  authenticates with its own `authentication_classes`, bound to the realm's
  transport, and never runs `StaffCookieAuthentication.validate_claims`.
  Do not treat a 200 from it as proof of a staff session.
- **Do not set `authentication_classes` on the realm.** A realm's
  attributes reach all five endpoints, login and refresh included, which
  would then authenticate with it. Put the check on the class your views
  list, as here.

The binding is one way. The default realm checks nothing, so a staff token
copied into the default cookie authenticates at the default realm's views.

Use a permission class when the question is who the user is, and this claim
pattern when the question is how the session began. The example uses both.

## See also

- {doc}`header-clients`, for a realm whose tokens travel in headers.
- [Realms: `signet_urls`](../reference/views.md#realms-signet_urls), for
  the reference.
