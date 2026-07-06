"""Unit tests for user-facing error message formatters."""

import io
from collections.abc import Callable

import pytest
from rich.console import Console

from bqcheck.error_handlers import (
    EXIT_AUTH_ERROR,
    EXIT_FILE_ERROR,
    EXIT_NETWORK_ERROR,
    handle_bigquery_forbidden_error,
    handle_bigquery_not_found_error,
    handle_bigquery_permission_error,
    handle_network_error,
    handle_timeout_error,
)


def render_handler(handler: Callable[[Console], int]) -> tuple[int, str]:
    console = Console(file=io.StringIO())
    exit_code = handler(console)

    return exit_code, console.file.getvalue()


def test_bigquery_permission_error_includes_fix_command():
    exit_code, output = render_handler(
        lambda console: handle_bigquery_permission_error(
            console,
            "my-project",
            "user@example.com",
        )
    )

    assert exit_code == EXIT_AUTH_ERROR
    assert "❌ Error: Insufficient BigQuery permissions" in output
    assert "gcloud projects add-iam-policy-binding my-project" in output
    assert "--member=user:user@example.com" in output
    assert "--role=roles/bigquery.metadataViewer" in output


@pytest.mark.parametrize(
    ("handler", "expected_exit_code", "expected_fragments"),
    [
        (
            lambda console: handle_bigquery_not_found_error(
                console,
                "nonexistent-project",
            ),
            EXIT_FILE_ERROR,
            [
                "❌ Error: Project 'nonexistent-project' not found",
                "Verify the project ID is correct",
            ],
        ),
        (
            lambda console: handle_bigquery_forbidden_error(
                console,
                "forbidden-project",
            ),
            EXIT_AUTH_ERROR,
            [
                "❌ Error: Access denied to project 'forbidden-project'",
                "Ensure you have access to this project",
            ],
        ),
        (
            handle_network_error,
            EXIT_NETWORK_ERROR,
            [
                "❌ Error: Unable to reach analysis server",
                "Check your internet connection",
                "Retry the scan when connection is restored",
                "Your token was not consumed",
            ],
        ),
        (
            handle_timeout_error,
            EXIT_NETWORK_ERROR,
            [
                "❌ Error: Sanity check timeout (>15 minutes)",
                "This may indicate a very large",
                "open a support request",
                "Your token was not consumed",
            ],
        ),
    ],
)
def test_error_handlers_return_expected_code_and_guidance(
    handler: Callable[[Console], int],
    expected_exit_code: int,
    expected_fragments: list[str],
):
    exit_code, output = render_handler(handler)

    assert exit_code == expected_exit_code
    for fragment in expected_fragments:
        assert fragment in output
