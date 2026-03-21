# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Ancilis, please report it responsibly.

**Email:** security@ancilis.ai

Please include:
- A description of the vulnerability
- Steps to reproduce
- Affected versions
- Any potential impact assessment

We will acknowledge receipt within 48 hours and aim to provide an initial assessment within 5 business days.

Please do **not** open a public GitHub issue for suspected vulnerabilities before coordinated disclosure review.

## Security Scope

Ancilis is a runtime control layer for AI agent tool calls. Security-relevant components include:

- **Policy engine** — evaluates tool calls against security controls
- **Evidence store** — DuckDB-backed with SHA-256 hash chain integrity
- **MCP middleware** — intercepts and enforces tool call decisions
- **Configuration parsing** — YAML config to resolved policy

## Technical Trust Boundaries

- Ancilis evaluates actions that flow through its explicit producers and middleware; it does not claim universal interception across arbitrary libraries or transports.
- HTTP blocking is limited to the explicit wrapped transport path. Observe/report mode is the supported default for HTTP activity.
- Evidence integrity depends on protecting the underlying evidence database and host environment in addition to the built-in hash chain.
- The TypeScript SDK is still preview and should not be presented as runtime-parity with the Python release path.

## Disclosure Policy

- We follow coordinated disclosure practices
- Critical vulnerabilities will be patched and released as soon as possible
- We will credit reporters in release notes (unless anonymity is requested)
- We may request a private reproducer or proof of concept to validate impact before public disclosure
