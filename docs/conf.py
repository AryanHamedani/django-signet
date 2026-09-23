"""Sphinx configuration for the django-signet documentation."""

import os
import sys
from importlib.metadata import version as _version
from pathlib import Path

import django

# autodoc imports django_signet, and importing its models needs configured
# settings. The docs directory goes on the path so the settings stub resolves.
sys.path.insert(0, str(Path(__file__).parent))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "_django_settings")
django.setup()

project = "django-signet"
author = "Aryan Hamedani"
copyright = "2026, django-signet contributors"
release = _version("django-signet")
version = ".".join(release.split(".")[:2])

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "sphinx_copybutton",
]
source_suffix = {".md": "markdown"}
exclude_patterns = ["_build", "superpowers", "examples", "_django_settings.py"]

myst_enable_extensions = ["colon_fence", "deflist"]
myst_heading_anchors = 3

autodoc_typehints = "description"
autodoc_member_order = "bysource"

# Django REST Framework publishes no Sphinx inventory, so it cannot be linked.
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "django": (
        "https://docs.djangoproject.com/en/stable/",
        "https://docs.djangoproject.com/en/stable/_objects/",
    ),
}

html_theme = "furo"
html_title = f"django-signet {release}"
