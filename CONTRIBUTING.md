# Contributing to Ancilis

Thanks for your interest in contributing.

## License

This project is licensed under Business Source License 1.1. By submitting a pull request, you agree that your contributions will be licensed under the same terms. See [LICENSE](LICENSE) for details.

## Getting Started

1. Fork and clone the repo
2. Install dependencies:
   ```bash
   pip install -e ".[dev]"
   npm install
   ```
3. Create a branch for your work
4. Make your changes
5. Run tests before submitting:
   ```bash
   pytest
   npm test
   ```
6. Open a pull request against `main`

## Code Style

Python: We use `ruff` for linting and formatting, `mypy` for type checking.
TypeScript: We use `eslint` and strict TypeScript compiler options.

## Reporting Issues

Open a GitHub issue. Include steps to reproduce, expected behavior, and actual behavior.
