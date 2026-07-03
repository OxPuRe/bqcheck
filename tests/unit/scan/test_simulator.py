"""
Unit tests for scan simulator.

Tests cover:
- Simulated scan execution
- Simulation notice and timing
"""

import time


class TestScanSimulator:
    """Test simulated scan functionality."""

    def test_simulator_imports(self):
        """Verify simulator module can be imported."""
        from bqcheck.scan.simulator import simulate_scan

        assert simulate_scan is not None

    def test_simulate_scan_takes_configured_time(self):
        """Simulated scan takes configured delay time."""
        from bqcheck.scan.simulator import DEFAULT_SIMULATION_DELAY, simulate_scan

        start_time = time.time()
        simulate_scan("test-project", "mock-token-xyz")
        elapsed = time.time() - start_time

        # Should take approximately DEFAULT_SIMULATION_DELAY seconds
        # Allow 90% to 150% of target delay (accounting for system overhead)
        expected_delay = DEFAULT_SIMULATION_DELAY
        assert expected_delay * 0.9 <= elapsed <= expected_delay * 1.5, (
            f"Scan took {elapsed:.2f}s "
            f"(expected ~{expected_delay}s with BQCHECK_SIMULATED_SCAN_DELAY)"
        )

    def test_simulate_scan_returns_success_result(self):
        """Simulated scan returns successful ScanResult."""
        from bqcheck.scan.simulator import simulate_scan

        result = simulate_scan("my-gcp-project", "mock-token-abc")

        assert result.success is True
        assert result.project_id == "my-gcp-project"
        assert result.simulated is True
        assert result.findings == []

    def test_simulate_scan_never_logs_token(self, caplog):
        """Simulator never logs ephemeral token."""
        import logging

        from bqcheck.scan.simulator import simulate_scan

        token = "secret-token-should-never-appear"

        with caplog.at_level(logging.DEBUG):
            simulate_scan("test-project", token)

        # Token should NEVER appear in logs
        for record in caplog.records:
            assert token not in record.message

    def test_simulator_displays_simulation_messages(self, capsys):
        """Simulator displays [SIMULATED] messages."""
        from bqcheck.scan.simulator import simulate_scan

        result = simulate_scan("my-test-project", "mock-token")

        # Capture stdout to verify simulation messages
        captured = capsys.readouterr()

        # Verify [SIMULATED] tag appears
        assert "[SIMULATED]" in captured.out
        assert "my-test-project" in captured.out
        assert "simulated scan for local testing" in captured.out
        assert "BQCHECK_REAL_SCAN=true" in captured.out
        assert result.simulated is True

    def test_simulate_scan_with_different_projects(self):
        """Simulator works with different project IDs."""
        from bqcheck.scan.simulator import simulate_scan

        projects = ["project-a", "project-b", "project-c"]

        for project_id in projects:
            result = simulate_scan(project_id, "mock-token")

            assert result.success is True
            assert result.project_id == project_id
            assert result.simulated is True
