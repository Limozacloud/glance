"""Linux/macOS binary classifier loader.

The built-in classifier catalog lives in linux_binary_data.py.
This module exposes the public API (default_classifiers()) and keeps
backward compatibility for any code that imports it.
"""

from __future__ import annotations

from .core.matchers import Classifier
from .linux_binary_data import LINUX_BINARY_CLASSIFIERS


def default_classifiers() -> list[Classifier]:
    """Return all built-in binary classifiers, in precedence order."""
    return list(LINUX_BINARY_CLASSIFIERS)
