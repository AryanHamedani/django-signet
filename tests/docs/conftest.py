"""Make the documentation's examples importable as ``examples.<name>``.

The pages render these files with ``literalinclude``; the tests in this
directory import and run them, so an example that stops working fails CI.
"""

import sys
from pathlib import Path

DOCS = Path(__file__).resolve().parents[2] / "docs"

if str(DOCS) not in sys.path:
    sys.path.insert(0, str(DOCS))
