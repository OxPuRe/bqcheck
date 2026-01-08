# bqaudit

[![CI](https://github.com/OxPuRe/bqaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/OxPuRe/bqaudit/actions/workflows/ci.yml)

BigQuery cost optimization audit tool with privacy-first architecture.

## Features

- Privacy-first metadata-only analysis (no raw data access)
- Client-side SHA-256 anonymization
- Token-based licensing system
- Actionable cost optimization recommendations

## Installation

### Using UV (Recommended)

```bash
uv pip install bqaudit
```

### Using pip

```bash
pip install bqaudit
```

## Usage

### Validate Access (Free)

```bash
bqaudit validate my-gcp-project
```

### Run Audit (Consumes 1 Token)

```bash
bqaudit scan my-gcp-project
```

### License Management

```bash
# Activate license
bqaudit license activate <master-license-key>

# Check token balance
bqaudit license status

# Revoke credentials
bqaudit license revoke
```

## Development

### Setup

```bash
# Clone repository
git clone https://github.com/your-org/bqaudit.git
cd bqaudit

# Install dependencies
uv sync

# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate   # Windows
```

### Testing

Run tests:
```bash
uv run pytest
```

Run tests with coverage:
```bash
uv run pytest --cov
```

Generate HTML coverage report:
```bash
uv run pytest --cov --cov-report=html
# Open htmlcov/index.html in browser
```

Run specific test markers:
```bash
uv run pytest -m "not slow"           # Skip slow tests
uv run pytest -m integration          # Run only integration tests
```

### Code Quality

Check code with Ruff:
```bash
uv run ruff check .
```

Auto-fix Ruff issues:
```bash
uv run ruff check --fix .
```

Format code with Ruff:
```bash
uv run ruff format .
```

Verify formatting:
```bash
uv run ruff format --check .
```

Type check with mypy:
```bash
uv run mypy src/
```

Run all quality checks:
```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pytest --cov
```

## Issues & Support

**Note:** Issues are tracked in the [bqaudit-server](https://github.com/OxPuRe/bqaudit-server/issues) repository.

Please submit all bug reports, feature requests, and questions there.

## Related Repositories

- [bqaudit-server](https://github.com/OxPuRe/bqaudit-server) (Private) - Server API

## License

MIT License (or proprietary - TBD)
