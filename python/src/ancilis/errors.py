"""Ancilis structured error code system.

Error codes are stable identifiers for actionable failure modes.
Each error prints with Rich formatting in the CLI:

  ANCILIS-E001  Cannot connect to platform at https://app.ancilis.ai
  → Check platform_url in ancilis.yaml. Is the platform running?
    https://docs.ancilis.ai/errors/e001
"""

from __future__ import annotations


class AncilisError(Exception):
    """Base class for all Ancilis SDK errors."""

    def __init__(
        self,
        code: str,
        message: str,
        suggestion: str | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.suggestion = suggestion
        self.docs_url = f"https://docs.ancilis.ai/errors/{code.lower()}"
        super().__init__(f"ANCILIS-{code}: {message}")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, message={self.message!r})"


# ---------------------------------------------------------------------------
# Connection errors
# ---------------------------------------------------------------------------


class ConnectionError(AncilisError):
    """E001 — Cannot reach the Ancilis platform."""

    def __init__(self, url: str) -> None:
        super().__init__(
            code="E001",
            message=f"Cannot connect to platform at {url}",
            suggestion="Check platform_url in ancilis.yaml. Is the platform running?",
        )


# ---------------------------------------------------------------------------
# Config errors
# ---------------------------------------------------------------------------


class ConfigError(AncilisError):
    """E002 / E003 — Configuration or overlay lookup failures."""


def config_invalid(validation_error: str) -> ConfigError:
    """E002 — ancilis.yaml failed schema validation."""
    return ConfigError(
        code="E002",
        message=f"Invalid ancilis.yaml: {validation_error}",
        suggestion="Run `ancilis init` to regenerate config",
    )


def overlay_not_found(name: str, available: list[str]) -> ConfigError:
    """E003 — Named overlay profile does not exist."""
    avail_str = ", ".join(available) if available else "none"
    return ConfigError(
        code="E003",
        message=f"Overlay profile not found: {name}",
        suggestion=f"Available overlays: {avail_str}. Check spelling",
    )


# ---------------------------------------------------------------------------
# Storage errors
# ---------------------------------------------------------------------------


class StorageError(AncilisError):
    """E004 — Evidence store or DuckDB failures."""

    def __init__(self, path: str) -> None:
        super().__init__(
            code="E004",
            message="Evidence store initialization failed",
            suggestion=f"Check DuckDB permissions at {path}. Ensure no other process holds the lock",
        )


# ---------------------------------------------------------------------------
# Auth errors
# ---------------------------------------------------------------------------


class AuthError(AncilisError):
    """E005 — Authentication / API key failures."""

    def __init__(self, platform_url: str = "https://app.ancilis.ai") -> None:
        super().__init__(
            code="E005",
            message="Authentication failed: invalid API key",
            suggestion=f"Generate a new key at {platform_url}/settings/api-keys",
        )


# ---------------------------------------------------------------------------
# Rate limit errors
# ---------------------------------------------------------------------------


class RateLimitError(AncilisError):
    """E006 — Platform rate limiting."""

    def __init__(self, retry_after: int) -> None:
        super().__init__(
            code="E006",
            message=f"Rate limited by platform (retry after {retry_after}s)",
            suggestion="Reduce scan frequency or contact support",
        )


# ---------------------------------------------------------------------------
# Scan errors
# ---------------------------------------------------------------------------


class ScanError(AncilisError):
    """E007 / E008 — Scan target failures."""


def scan_target_not_found(path: str) -> ScanError:
    """E007 — Scan target directory does not exist."""
    return ScanError(
        code="E007",
        message=f"Scan target directory not found: {path}",
        suggestion="Check the path exists and contains supported files",
    )


def no_supported_files(path: str) -> ScanError:
    """E008 — No scannable files found in directory."""
    return ScanError(
        code="E008",
        message=f"No supported files found in {path}",
        suggestion="Supported: .py, .ts, .js, .yaml. Check directory contents",
    )


# ---------------------------------------------------------------------------
# Upload errors
# ---------------------------------------------------------------------------


class UploadError(AncilisError):
    """E009 — Evidence upload failures."""

    def __init__(self, http_status: int) -> None:
        super().__init__(
            code="E009",
            message=f"Evidence upload failed: {http_status}",
            suggestion="Check network connectivity and API key permissions",
        )


# ---------------------------------------------------------------------------
# Version errors
# ---------------------------------------------------------------------------


class VersionError(AncilisError):
    """E010 — SDK or runtime version requirements not met."""

    def __init__(self, current: str, minimum: str) -> None:
        super().__init__(
            code="E010",
            message=f"SDK version {current} is unsupported. Minimum: {minimum}",
            suggestion="Run `pip install --upgrade ancilis` or `npm update ancilis`",
        )


# ---------------------------------------------------------------------------
# Warnings (W-codes) — not exceptions, returned as structured values
# ---------------------------------------------------------------------------


class AncilisWarning:
    """Structured warning — not raised, returned alongside results."""

    def __init__(self, code: str, message: str, suggestion: str | None = None) -> None:
        self.code = code
        self.message = message
        self.suggestion = suggestion
        self.docs_url = f"https://docs.ancilis.ai/errors/{code.lower()}"

    def __repr__(self) -> str:
        return f"AncilisWarning(code={self.code!r}, message={self.message!r})"

    def __str__(self) -> str:
        return f"ANCILIS-{self.code}: {self.message}"


def warn_no_overlays() -> AncilisWarning:
    """W001 — No overlay profiles configured."""
    return AncilisWarning(
        code="W001",
        message="No overlay profiles configured",
        suggestion="Scanning with defaults only. Run `ancilis init` to add overlays",
    )


def warn_sdk_update(current: str, latest: str) -> AncilisWarning:
    """W002 — Newer SDK version available."""
    return AncilisWarning(
        code="W002",
        message=f"SDK update available: {current} → {latest}",
        suggestion="Run `pip install --upgrade ancilis` or `npm update ancilis`",
    )


def warn_store_size(size_mb: float, limit_mb: float) -> AncilisWarning:
    """W003 — Evidence store approaching size limit."""
    return AncilisWarning(
        code="W003",
        message=f"Evidence store at {size_mb:.0f}MB (limit: {limit_mb:.0f}MB)",
        suggestion="Consider running `ancilis evidence prune`",
    )


# ---------------------------------------------------------------------------
# Rich CLI formatting
# ---------------------------------------------------------------------------


def format_error_rich(error: AncilisError) -> str:
    """Format an AncilisError for Rich console output.

    Returns a Rich markup string:
      [red bold]ANCILIS-E001[/]  message
      [yellow]→ suggestion[/]
      [blue]https://docs.ancilis.ai/errors/e001[/]
    """
    lines = [f"[red bold]ANCILIS-{error.code}[/]  {error.message}"]
    if error.suggestion:
        lines.append(f"[yellow]→ {error.suggestion}[/]")
    lines.append(f"[blue]{error.docs_url}[/]")
    return "\n".join(lines)


def format_warning_rich(warning: AncilisWarning) -> str:
    """Format an AncilisWarning for Rich console output."""
    lines = [f"[yellow bold]ANCILIS-{warning.code}[/]  {warning.message}"]
    if warning.suggestion:
        lines.append(f"[yellow]→ {warning.suggestion}[/]")
    lines.append(f"[blue]{warning.docs_url}[/]")
    return "\n".join(lines)


def print_error(error: AncilisError) -> None:
    """Print a structured AncilisError to stderr using Rich."""
    try:
        from rich.console import Console

        console = Console(stderr=True)
        console.print(format_error_rich(error))
    except ImportError:
        import sys

        print(str(error), file=sys.stderr)
        if error.suggestion:
            print(f"→ {error.suggestion}", file=sys.stderr)
        print(error.docs_url, file=sys.stderr)
