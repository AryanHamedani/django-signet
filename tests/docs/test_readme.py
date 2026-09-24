"""``README.md`` is also the PyPI description, so it cannot ``literalinclude``
the tested examples. These tests hold it to them instead, and check that every
link into the documentation site names a page and a heading that exist.
"""

import ast
import re
from pathlib import Path

import pytest
from examples import quickstart_settings

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
README = (ROOT / "README.md").read_text()
SITE = "https://django-signet.readthedocs.io/en/latest/"
LINKS = sorted(set(re.findall(re.escape(SITE) + r"([^)\s]*)", README)))
BLOCKS = re.findall(r"```python\n(.*?)```", README, re.DOTALL)


def _slug(heading):
    """MyST's default heading slug (``myst_parser``'s ``default_slugify``)."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower().replace(" ", "-"))


def _anchors(page):
    headings = re.findall(r"^#{1,3} (.+)$", page.read_text(), re.MULTILINE)
    return {_slug(heading) for heading in headings}


def test_the_readme_links_into_the_site():
    assert len(LINKS) >= 10


@pytest.mark.parametrize("link", LINKS)
def test_every_site_link_names_an_existing_page(link):
    path, _, anchor = link.partition("#")
    if path in {"", "index.html"}:
        return
    page = DOCS / path.replace(".html", ".md")
    assert page.is_file(), link
    if anchor:
        assert anchor in _anchors(page), link


def test_the_settings_match_the_quickstart():
    namespace = {
        node.targets[0].id: ast.literal_eval(node.value)
        for node in ast.parse(BLOCKS[0]).body
        if isinstance(node, ast.Assign)
    }
    assert namespace["REST_FRAMEWORK"] == quickstart_settings.REST_FRAMEWORK
    for app in ("rest_framework", "django_signet"):
        assert app in namespace["INSTALLED_APPS"]
        assert app in quickstart_settings.INSTALLED_APPS


def test_the_urlconf_matches_the_quickstart():
    mount = 'path("api/auth/", include("django_signet.urls"))'
    assert mount in BLOCKS[1]
    assert mount in (DOCS / "examples" / "quickstart_urls.py").read_text()


def test_the_readme_uses_no_sphinx_only_syntax():
    assert "```{" not in README
    assert "{doc}`" not in README
