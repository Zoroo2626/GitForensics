# Contributing to GitForensics

Thank you for your interest in contributing to GitForensics.

## Development Setup

GitForensics requires Python 3.10 or newer and a local `git` executable.

1. Clone the repository:

   ```bash
   git clone https://github.com/GitForensics/GitForensics.git
   cd GitForensics
   ```

2. Create and activate a virtual environment:

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```

3. Install the package in editable mode with development dependencies:

   ```bash
   python -m pip install -e .
   python -m pip install pytest pytest-cov ruff mypy build
   ```

## Code Quality Standards

All contributions must pass linting, formatting, type checking, and unit testing before being merged.

### 1. Formatting and Linting

GitForensics uses `ruff` for code formatting and linting.

Check lint rules:

```bash
python -m ruff check .
```

Check code formatting:

```bash
python -m ruff format --check .
```

Auto-fix format issues:

```bash
python -m ruff format .
```

### 2. Static Type Checking

GitForensics uses `mypy` in strict mode with Python 3.10 target semantics.

Run type checking:

```bash
python -m mypy src
```

All functions must include type annotations for parameters and return values.

### 3. Unit and Integration Tests

GitForensics uses `pytest` for unit and integration testing.

Run test suite:

```bash
python -m pytest
```

Run test suite with coverage:

```bash
python -m pytest --cov=gitforensics --cov-report=term-missing
```

Code coverage must remain at or above 90% total statement coverage.

### 4. Package Build Verification

Verify that distribution packages build cleanly:

```bash
python -m build
```

## Pull Request Guidelines

Before submitting a pull request, ensure that:

1. All tests pass (`python -m pytest`).
2. Ruff check and format check pass without errors.
3. Mypy strict type checking passes without errors.
4. Package build succeeds (`python -m build`).
5. New functionality or bug fixes include corresponding unit tests.
6. Documentation is updated to reflect any CLI or behavior changes.
7. No security protections or resource limits are weakened.
8. No em dash characters are used in markdown documentation files.
