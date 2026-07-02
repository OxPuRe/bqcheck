# bqcheck

[![CI](https://github.com/OxPuRe/bqcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/OxPuRe/bqcheck/actions/workflows/ci.yml)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)]()

**Open-source CLI client** for BigQuery sanity checks with privacy-first architecture.

## Features

- 🔒 **Privacy-first**: Metadata-only analysis (no raw data access)
- 🔐 **Client-side anonymization**: SHA-256 hashing of project/table IDs
- 🎫 **Token-based licensing**: Pay-per-scan model
- 💰 **Actionable recommendations**: Storage, partitioning, clustering, query optimizations
- 📊 **Markdown reports**: Well-formatted sanity check reports with savings breakdown
- ✅ **Free validation**: Check BigQuery access before purchasing tokens

## Architecture

bqcheck is a client-server architecture:

- **Client** (this repo): Open-source CLI tool that extracts BigQuery metadata locally
- **Server** ([bqcheck-server](https://github.com/OxPuRe/bqcheck-server)): Proprietary analysis engine that analyzes metadata and generates recommendations

The client anonymizes all project and table identifiers before sending metadata to the server, ensuring your data stays private.

## Installation

### Using UV (Recommended)

```bash
uv pip install bqcheck
```

### Using pip

```bash
pip install bqcheck
```

## Usage

### Validate Access (Free)

Check BigQuery access and permissions without consuming tokens:

```bash
bqcheck validate --project my-gcp-project
```

Validate multi-project setup:

```bash
bqcheck validate --project storage-project --query-project processing-project
```

Show detailed validation steps:

```bash
bqcheck validate --project my-gcp-project --verbose
```

### Run Sanity Check (Consumes 1 Token)

**Single-project scan:**
```bash
bqcheck scan --project my-gcp-project
```

**Multi-project scan** (for separated storage/processing architectures):
```bash
bqcheck scan --project storage-project --query-project processing-project
```

Use `--query-project` when your tables are stored in one project but queries run in another. This dramatically improves query-based recommendations (materialized views, clustering opportunities).

### License Management

**Get a license:**
- 🚧 **WIP** - License distribution system coming soon

**Activate your license:**
```bash
bqcheck license activate sk_live_...
```

**Check your token balance:**
```bash
bqcheck license status
```

**Revoke credentials:**
```bash
bqcheck license revoke
```

Credentials are stored locally in `~/.bqcheck/credentials.json`

### Custom Output Path

Save sanity check reports to a custom location:

```bash
# Save to specific file
bqcheck scan --project my-gcp-project --output reports/sanity-check.md

# Save to specific directory (auto-generates filename)
bqcheck scan --project my-gcp-project --output-dir ./reports/

# Force overwrite existing file
bqcheck scan --project my-gcp-project --output report.md --force
```

## Configuration

### Environment Variables

Optional environment variables for advanced users:

- `BQCHECK_API_URL`: Override default server URL (default: production Cloud Run endpoint)
- `BQCHECK_REAL_MODE`: Set to `"false"` for mock server mode (testing only, default: `"true"`)
- `BQCHECK_REAL_SCAN`: Set to `"false"` for simulated BigQuery scan (testing only, default: `"true"`)

**Example (development/testing):**
```bash
export BQCHECK_REAL_MODE="false"
export BQCHECK_REAL_SCAN="false"
bqcheck scan --project test-project
```

## Development

### Setup

```bash
# Clone repository
git clone https://github.com/OxPuRe/bqcheck.git
cd bqcheck

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

## How It Works

1. **Extract metadata** - Client queries BigQuery INFORMATION_SCHEMA for table/query metadata
2. **Anonymize locally** - SHA-256 hash all project and table identifiers
3. **Send to server** - Encrypted HTTPS request with ephemeral token
4. **Analyze** - Server runs 6 detection algorithms (storage, partitioning, clustering, queries, temporal)
5. **Receive recommendations** - Markdown report with prioritized optimizations and EUR savings
6. **Auto-renew token** - Server returns fresh ephemeral token for next scan

**Privacy guarantee:** Only metadata and statistics are sent. No table data, query results, or business logic ever leaves your GCP project.

## Related Repositories

- [bqcheck-server](https://github.com/OxPuRe/bqcheck-server) - Proprietary analysis engine and API server

## Support

- **Issues**: [GitHub Issues](https://github.com/OxPuRe/bqcheck-server/issues) (tracked in server repo)
- **Documentation**: See [server README](https://github.com/OxPuRe/bqcheck-server#license--token-management) for license system details

## License

MIT License - Client CLI tool is open source

Note: The server-side analysis engine is proprietary. See [bqcheck-server](https://github.com/OxPuRe/bqcheck-server) for details.
