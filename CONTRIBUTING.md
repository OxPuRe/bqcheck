# Contributing to bqaudit

Thank you for your interest in contributing to bqaudit! 🎉

## 🌟 How Can I Contribute?

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/OxPuRe/bqaudit/issues)
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Python version, OS, and bqaudit version
   - Relevant logs or error messages

### Suggesting Features

We welcome feature suggestions! Please:
1. Check existing issues first
2. Create a new issue with the `enhancement` label
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

# Install dependencies
cd cli
uv venv
uv pip install -e ".[dev]"

# Install shared module
cd ../shared
uv venv
uv pip install -e ".[dev]"
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
├── cli/               # CLI application
│   ├── src/bqaudit/   # Source code
│   └── tests/         # Tests
├── shared/            # Shared schemas
│   ├── src/bqaudit_shared/
│   └── tests/
└── docs/              # Documentation
```

## ✅ What We're Looking For

**High Priority:**
- Additional audit rules (e.g., unused tables, inefficient queries)
- Improved metadata extraction logic
- Better error handling and user messages
- Documentation improvements

**Medium Priority:**
- Performance optimizations
- Support for more BigQuery features
- Additional export formats

**Low Priority:**
- New CLI commands (discuss first)
- Breaking changes (discuss first)

## 🚫 What We Won't Accept

- Changes to the credit/pricing system (server-side only)
- Features that require accessing actual table data
- Dependencies on closed-source libraries
- Breaking changes without discussion

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## 💬 Questions?

Open an issue with the `question` label or reach out to the maintainers.

Thank you for contributing! 🙏
