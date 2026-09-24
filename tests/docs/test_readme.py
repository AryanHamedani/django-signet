"""``README.md`` is also the PyPI description, so it cannot ``literalinclude``
the tested examples. These tests hold it to them instead, and check that every
link is absolute (PyPI resolves no relative link) and that every link into the
documentation site names a published page and a heading that exist on it.
"""

import ast
import re
import unicodedata
from pathlib import Path

import pytest
from examples import quickstart_settings

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
README = (ROOT / "README.md").read_text()
SITE = "https://django-signet.readthedocs.io/en/latest/"
LINKS = sorted(set(re.findall(re.escape(SITE) + r"([^)\s]*)", README)))
BLOCKS = re.findall(r"```python\n(.*?)```", README, re.DOTALL)


LINK_TARGETS = re.findall(r"\]\(([^)\s]+)\)", README)


def _html_id(heading):
    """The ``id`` Sphinx gives a section in the HTML: ``docutils.nodes.make_id``
    of its title. An ASCII copy, because the test job does not install
    docutils; ``test_html_id_matches_docutils`` holds it to the real one."""
    text = unicodedata.normalize("NFKD", heading.lower())
    text = text.encode("ascii", "ignore").decode("ascii")
    text = re.sub("[^a-z0-9]+", "-", " ".join(text.split()))
    return re.sub("^[-0-9]+|-+$", "", text)


def _headings(page):
    return re.findall(r"^#{1,6} (.+)$", page.read_text(), re.MULTILINE)


def _anchors(page):
    return {_html_id(heading) for heading in _headings(page)}


def _published_pages():
    return [
        page
        for page in DOCS.rglob("*.md")
        if not {"superpowers", "_build", "examples"} & set(page.parts)
    ]


def test_html_id_matches_docutils():
    nodes = pytest.importorskip("docutils.nodes")
    for page in _published_pages():
        for heading in _headings(page):
            assert _html_id(heading) == nodes.make_id(heading), (page, heading)


def test_the_anchor_is_the_html_id_not_the_myst_slug():
    anchors = _anchors(DOCS / "howto" / "deploying.md")
    assert "leave-cookie-domain-unset-unless-you-need-it" in anchors
    assert "leave-cookie_domain-unset-unless-you-need-it" not in anchors


def test_every_link_is_absolute():
    assert LINK_TARGETS
    for target in LINK_TARGETS:
        assert target.startswith("https://"), target


def test_no_link_points_at_the_internal_records():
    for target in LINK_TARGETS:
        assert "superpowers" not in target, target


def test_the_readme_links_into_the_site():
    assert len(LINKS) >= 10


@pytest.mark.parametrize("link", LINKS)
def test_every_site_link_names_an_existing_page(link):
    path, _, anchor = link.partition("#")
    if path in {"", "index.html"}:
        return
    page = DOCS / path.replace(".html", ".md")
    assert page in _published_pages(), link
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
