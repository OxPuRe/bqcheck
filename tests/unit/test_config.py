"""
Unit tests for bqaudit configuration module.

Tests logging configuration functionality including verbose mode.
"""

import logging

import pytest

from bqaudit.config import configure_logging


class TestConfigureLogging:
    """Test configure_logging function."""

    def test_configure_logging_verbose_true(self):
        """Test logging configured to DEBUG when verbose=True."""
        logger = configure_logging(verbose=True)

        assert logger.level == logging.DEBUG
        assert logger.name == "bqaudit"

    def test_configure_logging_verbose_false(self):
        """Test logging configured to INFO when verbose=False."""
        logger = configure_logging(verbose=False)

        assert logger.level == logging.INFO
        assert logger.name == "bqaudit"

    def test_configure_logging_default(self):
        """Test logging configured to INFO by default (no args)."""
        logger = configure_logging()

        assert logger.level == logging.INFO
        assert logger.name == "bqaudit"

    def test_configure_logging_has_handler(self):
        """Test logger has at least one handler configured."""
        logger = configure_logging()

        assert len(logger.handlers) > 0

    def test_configure_logging_handler_format(self):
        """Test logger handler has correct format string."""
        logger = configure_logging(verbose=True)

        # Get the first handler
        handler = logger.handlers[0]
        formatter = handler.formatter

        assert formatter is not None
        # Check format string contains expected components
        format_string = formatter._fmt
        assert "%(asctime)s" in format_string
        assert "%(name)s" in format_string
        assert "%(levelname)s" in format_string
        assert "%(message)s" in format_string

    def test_configure_logging_returns_same_logger(self):
        """Test multiple calls return the same logger instance."""
        logger1 = configure_logging(verbose=True)
        logger2 = configure_logging(verbose=False)

        assert logger1 is logger2
        # Level should be updated on second call
        assert logger2.level == logging.INFO
