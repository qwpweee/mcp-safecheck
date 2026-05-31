"""Public package interface for mcp-safecheck."""

from .scanner import Finding, scan_paths

__all__ = ["Finding", "scan_paths"]
