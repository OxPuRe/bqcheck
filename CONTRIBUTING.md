# Contributing to bqaudit

Thank you for your interest in contributing to bqaudit! 🎉

## 🌟 How Can I Contribute?

### Reporting Bugs

**Note:** All issues (client and server) are tracked in the [bqaudit-server repository](https://github.com/OxPuRe/bqaudit-server/issues).

1. Check if the bug has already been reported
2. If not, [create a new issue](https://github.com/OxPuRe/bqaudit-server/issues/new/choose) with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Python version, OS, and bqaudit version
   - Relevant logs or error messages

### Suggesting Features

We welcome feature suggestions! Please:
1. Check [existing issues](https://github.com/OxPuRe/bqaudit-server/issues) first
2. [Create a new feature request](https://github.com/OxPuRe/bqaudit-server/issues/new/choose)
3. Describe the use case and expected behavior
4. Explain why this would be useful to other users

### Pull Requests

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/my-feature
   ```
3. **Make your changes**:
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation if needed
4. **Run tests**:
   ```bash
   uv run pytest
   uv run ruff check .
   ```
5. **Commit** with clear messages:
   ```bash
   git commit -m "Add feature: description"
   ```
6. **Push** and create a Pull Request

## 🧪 Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/bqaudit.git
cd bqaudit

# Install dependencies with UV
uv sync

# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate  # Windows

# Run tests to verify setup
uv run pytest
```

## 📝 Code Style

We use:
- **Ruff** for linting and formatting
- **mypy** for type checking (encouraged but not required)
- **pytest** for testing

Run before committing:
```bash
uv run ruff check .
uv run ruff format .
uv run pytest
```

## 🧩 Project Structure

```
bqaudit/
├── src/bqaudit/       # Source code
│   ├── api/           # Server API client
│   ├── cli/           # CLI commands
│   ├── scanner/       # BigQuery metadata extraction
│   ├── license/       # License management
│   └── constants.py   # Configuration constants
├── tests/             # Test suite
│   ├── unit/          # Unit tests
│   └── integration/   # Integration tests
├── pyproject.toml     # Project configuration (UV)
└── uv.lock            # Dependency lock file
```

## ✅ What We're Looking For

**High Priority:**
- Improved metadata extraction logic (more INFORMATION_SCHEMA queries)
- Better error handling and user messages
- Documentation improvements
- Test coverage improvements
- Bug fixes

**Medium Priority:**
- Performance optimizations (parallel extraction, caching)
- Support for more BigQuery features (views, UDFs, etc.)
- Additional report formats (JSON, CSV, HTML)
- CLI UX improvements

**Low Priority:**
- New CLI commands (discuss first in an issue)
- Breaking changes (requires discussion and deprecation period)

## 🚫 What We Won't Accept

- Changes to licensing/token system (server-side only)
- Features that access actual table data (privacy violation)
- Features that bypass server audit engine
- Dependencies on closed-source libraries
- Breaking changes without prior discussion

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## 💬 Questions?

Open an issue with the `question` label or reach out to the maintainers.

Thank you for contributing! 🙏
