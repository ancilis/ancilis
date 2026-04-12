/**
 * Ancilis structured error hierarchy.
 *
 * All SDK errors extend AncilisError and carry a structured error code,
 * human-readable message, optional fix suggestion, and documentation URL.
 *
 * Error codes:
 *   E001 — Platform connection failed
 *   E002 — Invalid ancilis.yaml configuration
 *   E003 — Overlay profile not found
 *   E004 — Evidence store initialization failed (DuckDB)
 *   E005 — Authentication failed (invalid API key)
 *   E006 — Rate limited by platform
 *   E007 — Scan target directory not found
 *   E008 — No supported files found in scan directory
 *   E009 — Evidence upload failed
 *   E010 — SDK/Node version unsupported
 *
 * Warning codes:
 *   W001 — No overlay profiles configured
 *   W002 — SDK update available
 *   W003 — Evidence store approaching size limit
 */

// ---------------------------------------------------------------------------
// ANSI color helpers (no external dependency required)
// ---------------------------------------------------------------------------

function ansi(codes: string[], text: string): string {
  return `\u001b[${codes.join(";")}m${text}\u001b[0m`;
}

/** Red text — used for error code + message line */
export function red(text: string): string {
  return ansi(["31"], text);
}

/** Yellow text — used for suggestion line */
export function yellow(text: string): string {
  return ansi(["33"], text);
}

/** Blue text — used for docs URL */
export function blue(text: string): string {
  return ansi(["34"], text);
}

// ---------------------------------------------------------------------------
// Base class
// ---------------------------------------------------------------------------

/**
 * Base class for all Ancilis SDK errors.
 *
 * Every error carries:
 * - `code`       — e.g. "E001"
 * - `suggestion` — optional actionable fix hint
 * - `docsUrl`    — canonical docs page for this code
 */
export class AncilisError extends Error {
  readonly code: string;
  readonly suggestion?: string;
  readonly docsUrl: string;

  constructor(code: string, message: string, suggestion?: string) {
    super(`ANCILIS-${code}: ${message}`);
    this.code = code;
    this.suggestion = suggestion;
    this.docsUrl = `https://docs.ancilis.ai/errors/${code.toLowerCase()}`;
    this.name = "AncilisError";
    // Restore prototype chain (required when extending built-in Error in TS)
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /**
   * Render a multi-line, colour-formatted string suitable for CLI output.
   *
   * Format:
   *   ANCILIS-E001  Cannot connect to platform at https://app.ancilis.ai
   *   → Check platform_url in ancilis.yaml. Is the platform running?
   *     https://docs.ancilis.ai/errors/e001
   */
  format(colorEnabled = true): string {
    const color = colorEnabled;
    const header = color
      ? `${red(`ANCILIS-${this.code}`)}  ${this.message.replace(`ANCILIS-${this.code}: `, "")}`
      : this.message;
    const lines = [header];
    if (this.suggestion) {
      lines.push(color ? yellow(`→ ${this.suggestion}`) : `→ ${this.suggestion}`);
    }
    lines.push(color ? blue(`  ${this.docsUrl}`) : `  ${this.docsUrl}`);
    return lines.join("\n");
  }
}

// ---------------------------------------------------------------------------
// Subclasses
// ---------------------------------------------------------------------------

/**
 * E001 — Cannot connect to platform.
 * @param url The platform URL that was unreachable.
 */
export class ConnectionError extends AncilisError {
  constructor(url: string, cause?: unknown) {
    super(
      "E001",
      `Cannot connect to platform at ${url}`,
      "Check platform_url in ancilis.yaml. Is the platform running?",
    );
    this.name = "ConnectionError";
    if (cause instanceof Error) this.cause = cause;
  }
}

/**
 * E002 — Invalid ancilis.yaml configuration.
 * @param validationError Human-readable description of the validation failure.
 */
export class ConfigError extends AncilisError {
  constructor(validationError: string) {
    super(
      "E002",
      `Invalid ancilis.yaml: ${validationError}`,
      "Run `ancilis init` to regenerate config",
    );
    this.name = "ConfigError";
  }
}

/**
 * E003 — Overlay profile not found.
 * @param name The overlay name that was not found.
 * @param available List of available overlay names (optional).
 */
export class OverlayNotFoundError extends AncilisError {
  constructor(name: string, available?: string[]) {
    const suggestion = available?.length
      ? `Available overlays: ${available.join(", ")}. Check spelling`
      : "Check spelling or run `ancilis config validate` to list available overlays";
    super("E003", `Overlay profile not found: ${name}`, suggestion);
    this.name = "OverlayNotFoundError";
  }
}

/**
 * E004 — Evidence store initialization failed (DuckDB).
 * @param path The evidence store path that failed.
 */
export class StorageError extends AncilisError {
  constructor(path: string, cause?: unknown) {
    super(
      "E004",
      "Evidence store initialization failed",
      `Check DuckDB permissions at ${path}. Ensure no other process holds the lock`,
    );
    this.name = "StorageError";
    if (cause instanceof Error) this.cause = cause;
  }
}

/**
 * E005 — Authentication failed (invalid API key).
 * @param platformUrl The platform URL where a new key can be generated.
 */
export class AuthError extends AncilisError {
  constructor(platformUrl: string) {
    super(
      "E005",
      "Authentication failed: invalid API key",
      `Generate a new key at ${platformUrl}/settings/api-keys`,
    );
    this.name = "AuthError";
  }
}

/**
 * E006 — Rate limited by platform.
 * @param retryAfterSeconds Seconds until the client may retry.
 */
export class RateLimitError extends AncilisError {
  constructor(retryAfterSeconds?: number) {
    const msg = retryAfterSeconds !== undefined
      ? `Rate limited by platform (retry after ${retryAfterSeconds}s)`
      : "Rate limited by platform";
    super("E006", msg, "Reduce scan frequency or contact support");
    this.name = "RateLimitError";
  }
}

/**
 * E007 — Scan target directory not found or empty.
 * @param path The path that was not found.
 */
export class ScanError extends AncilisError {
  constructor(path: string) {
    super(
      "E007",
      `Scan target directory not found: ${path}`,
      "Check the path exists and contains supported files",
    );
    this.name = "ScanError";
  }
}

/**
 * E008 — No supported files found in scan directory.
 * @param path The directory that was scanned.
 */
export class UnsupportedFileError extends AncilisError {
  constructor(path: string) {
    super(
      "E008",
      `No supported files found in ${path}`,
      "Supported: .py, .ts, .js, .yaml. Check directory contents",
    );
    this.name = "UnsupportedFileError";
  }
}

/**
 * E009 — Evidence upload failed.
 * @param httpStatus HTTP status code returned by the platform.
 */
export class UploadError extends AncilisError {
  constructor(httpStatus: number | string) {
    super(
      "E009",
      `Evidence upload failed: ${httpStatus}`,
      "Check network connectivity and API key permissions",
    );
    this.name = "UploadError";
  }
}

/**
 * E010 — SDK/Node version unsupported.
 * @param current Current Node.js version string.
 * @param minimum Minimum required version string.
 */
export class VersionError extends AncilisError {
  constructor(current: string, minimum: string) {
    super(
      "E010",
      `Node.js version ${current} is unsupported. Minimum: ${minimum}`,
      "Upgrade Node.js to at least the minimum supported version",
    );
    this.name = "VersionError";
  }
}

// ---------------------------------------------------------------------------
// Warning codes (W-codes) — not thrown, returned as structured values
// ---------------------------------------------------------------------------

/**
 * Structured warning — not raised as an exception, returned alongside results.
 *
 * Warning codes:
 *   W001 — No overlay profiles configured
 *   W002 — SDK update available
 *   W003 — Evidence store approaching size limit
 */
export class AncilisWarning {
  readonly code: string;
  readonly message: string;
  readonly suggestion?: string;
  readonly docsUrl: string;

  constructor(code: string, message: string, suggestion?: string) {
    this.code = code;
    this.message = message;
    this.suggestion = suggestion;
    this.docsUrl = `https://docs.ancilis.ai/errors/${code.toLowerCase()}`;
  }

  toString(): string {
    return `ANCILIS-${this.code}: ${this.message}`;
  }

  /**
   * Render a multi-line, colour-formatted string suitable for CLI output.
   */
  format(colorEnabled = true): string {
    const header = colorEnabled
      ? `${yellow(`ANCILIS-${this.code}`)}  ${this.message}`
      : `ANCILIS-${this.code}: ${this.message}`;
    const lines = [header];
    if (this.suggestion) {
      lines.push(colorEnabled ? yellow(`→ ${this.suggestion}`) : `→ ${this.suggestion}`);
    }
    lines.push(colorEnabled ? blue(`  ${this.docsUrl}`) : `  ${this.docsUrl}`);
    return lines.join("\n");
  }
}

/**
 * W001 — No overlay profiles configured.
 */
export function warnNoOverlays(): AncilisWarning {
  return new AncilisWarning(
    "W001",
    "No overlay profiles configured",
    "Scanning with defaults only. Run `ancilis init` to add overlays",
  );
}

/**
 * W002 — Newer SDK version available.
 * @param current Current installed version.
 * @param latest Available latest version.
 */
export function warnSdkUpdate(current: string, latest: string): AncilisWarning {
  return new AncilisWarning(
    "W002",
    `SDK update available: ${current} → ${latest}`,
    "Run `npm update ancilis` to upgrade",
  );
}

/**
 * W003 — Evidence store approaching size limit.
 * @param sizeMb Current store size in megabytes.
 * @param limitMb Configured size limit in megabytes.
 */
export function warnStoreSize(sizeMb: number, limitMb: number): AncilisWarning {
  return new AncilisWarning(
    "W003",
    `Evidence store at ${Math.round(sizeMb)}MB (limit: ${Math.round(limitMb)}MB)`,
    "Consider running `ancilis evidence prune`",
  );
}
