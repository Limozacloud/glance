"""Linux/macOS binary classifier loader.

The built-in classifier catalog lives in linux_binary_data.py as plain dicts.
This module converts them to Classifier objects and exposes the public API.
"""

from __future__ import annotations

from .core.loader import classifiers_from_dicts
from .core.matchers import Classifier
from .linux_binary_data import LINUX_BINARY_CLASSIFIERS


def default_classifiers() -> list[Classifier]:
    """Return all built-in binary classifiers, in precedence order."""
    return classifiers_from_dicts(LINUX_BINARY_CLASSIFIERS)
