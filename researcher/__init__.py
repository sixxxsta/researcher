"""Readonly forensic log scanner for mounted Linux server backups."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("researcher")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"
