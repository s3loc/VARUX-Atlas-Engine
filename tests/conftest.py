"""Test configuration helpers for import resolution."""

from pathlib import Path
import sys

# Ensure the repository root is on sys.path so the ``varux`` package can be imported
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
