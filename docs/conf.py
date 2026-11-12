"""Sphinx configuration for the pygrindvakt documentation.

Build with the project virtualenv so ``pygrindvakt`` is importable::

    .venv/bin/python -m sphinx -b html docs docs/_build/html
"""

import importlib.metadata

project = "pygrindvakt"
author = "Kushal Das"
copyright = "2026, Kushal Das"

try:
    release = importlib.metadata.version("pygrindvakt")
except importlib.metadata.PackageNotFoundError:
    release = "0.5.0"
version = ".".join(release.split(".")[:2])

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
]

# Default to the Python domain so bare ``:class:`` / ``:func:`` roles resolve.
primary_domain = "py"
default_role = "py:obj"

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

# autodoc settings (used for the small parts that carry runtime docstrings).
autodoc_member_order = "bysource"
autodoc_typehints = "description"

html_theme = "furo"
html_title = f"pygrindvakt {release}"
html_static_path = ["_static"]

# Keep the build quiet: these are documented in prose, not as resolvable xrefs.
nitpicky = False
