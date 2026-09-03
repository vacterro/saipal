"""SAIPAL engine -- the runtime behind the forensic protocol observer.

Standard library only. No pip dependencies, ever. Python 3.8+.

The engine is deliberately NOT imported from the SAIPEN engine under audit:
an observer must not borrow the write machinery of the system it observes.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
