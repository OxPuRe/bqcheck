# bqaudit

[![CI](https://github.com/OxPuRe/bqaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/OxPuRe/bqaudit/actions/workflows/ci.yml)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)]()

**Open-source CLI client** for BigQuery cost optimization audits with privacy-first architecture.

## Features

- 🔒 **Privacy-first**: Metadata-only analysis (no raw data access)
- 🔐 **Client-side anonymization**: SHA-256 hashing of project/table IDs
- 🎫 **Token-based licensing**: Pay-per-scan model
- 💰 **Actionable recommendations**: Storage, partitioning, clustering, query optimizations
- 📊 **Markdown reports**: Well-formatted audit reports with savings breakdown
- ✅ **Free validation**: Check BigQuery access before purchasing tokens

## Architecture

bqaudit is a client-server architecture:

- **Client** (this repo): Open-source CLI tool that extracts BigQuery metadata locally
- **Server** ([bqaudit-server](https://github.com/OxPuRe/bqaudit-server)): Proprietary audit engine that analyzes metadata and generates recommendations

The client anonymizes all project and table identifiers before sending metadata to the server, ensuring your data stays private.

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

Check BigQuery access and permissions without consuming tokens:

```bash
bqaudit validate --project my-gcp-project
```

Show detailed validation steps:

```bash
bqaudit validate --project my-gcp-project --verbose
```

### Run Audit (Consumes 1 Token)

```bash
bqaudit scan --project my-gcp-project
```

### License Management

**Get a license:**
- 🚧 **WIP** - License distribution system coming soon

**Activate your license:**
```bash
bqaudit license activate sk_live_...
```

**Check your token balance:**
```bash
bqaudit license status
```

**Revoke credentials:**
```bash
bqaudit license revoke
```

Credentials are stored locally in `~/.bqaudit/credentials.json`

### Custom Output Path

Save audit reports to a custom location:

```bash
# Save to specific file
bqaudit scan --project my-gcp-project --output reports/audit.md

# Save to specific directory (auto-generates filename)
bqaudit scan --project my-gcp-project --output-dir ./reports/

# Force overwrite existing file
bqaudit scan --project my-gcp-project --output report.md --force
```

## Configuration

### Environment Variables

Optional environment variables for advanced users:

- `BQAUDIT_API_URL`: Override default server URL (default: production Cloud Run endpoint)
- `BQAUDIT_REAL_MODE`: Set to `"false"` for mock server mode (testing only, default: `"true"`)
- `BQAUDIT_REAL_SCAN`: Set to `"false"` for simulated BigQuery scan (testing only, default: `"true"`)

**Example (development/testing):**
```bash
export BQAUDIT_REAL_MODE="false"
export BQAUDIT_REAL_SCAN="false"
bqaudit scan --project test-project
```

## Development

### Setup

```bash
# Clone repository
git clone https://github.com/OxPuRe/bqaudit.git
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

## How It Works

1. **Extract metadata** - Client queries BigQuery INFORMATION_SCHEMA for table/query metadata
2. **Anonymize locally** - SHA-256 hash all project and table identifiers
3. **Send to server** - Encrypted HTTPS request with ephemeral token
4. **Analyze** - Server runs 6 detection algorithms (storage, partitioning, clustering, queries, temporal)
5. **Receive recommendations** - Markdown report with prioritized optimizations and EUR savings
6. **Auto-renew token** - Server returns fresh ephemeral token for next scan

**Privacy guarantee:** Only metadata and statistics are sent. No table data, query results, or business logic ever leaves your GCP project.

## Related Repositories

- [bqaudit-server](https://github.com/OxPuRe/bqaudit-server) - Proprietary audit engine and API server

## Support

- **Issues**: [GitHub Issues](https://github.com/OxPuRe/bqaudit-server/issues) (tracked in server repo)
- **Documentation**: See [server README](https://github.com/OxPuRe/bqaudit-server#license--token-management) for license system details

## License

MIT License - Client CLI tool is open source

Note: The server-side audit engine is proprietary. See [bqaudit-server](https://github.com/OxPuRe/bqaudit-server) for details.

