"""Package scanner. Expose `Vulnerability` immédiatement ; `Scanner` est
importable via `from scanner.core import Scanner` (pas exposé ici pour éviter
un cycle d'import avec le package `evaluator`).
"""
from .vulnerability import Vulnerability

__all__ = ["Vulnerability"]


def __getattr__(name):
    # Import paresseux de Scanner pour éviter les dépendances circulaires.
    if name == "Scanner":
        from .core import Scanner
        return Scanner
    raise AttributeError(f"module 'scanner' has no attribute {name!r}")
