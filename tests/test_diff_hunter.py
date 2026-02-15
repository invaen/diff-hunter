"""Tests for diff-hunter core functionality."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from diff_hunter import DiffHunter, C


class TestDomainValidation:
    """Tests for add_target domain validation."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.hunter = DiffHunter()
        self.hunter.data_dir = Path(self.tmpdir)
        self.hunter.targets_file = self.hunter.data_dir / 'targets.json'
        self.hunter.history_dir = self.hunter.data_dir / 'history'
        self.hunter.history_dir.mkdir(exist_ok=True)
        self.hunter.alerts_file = self.hunter.data_dir / 'alerts.json'
        self.hunter.targets = {}

    @patch.object(DiffHunter, 'scan_target')
    def test_valid_domain(self, mock_scan):
        self.hunter.add_target('example.com')
        assert 'example.com' in self.hunter.targets

    @patch.object(DiffHunter, 'scan_target')
    def test_valid_subdomain(self, mock_scan):
        self.hunter.add_target('sub.example.com')
        assert 'sub.example.com' in self.hunter.targets

    def test_invalid_domain_no_dot(self):
        self.hunter.add_target('localhost')
        assert 'localhost' not in self.hunter.targets

    def test_invalid_domain_spaces(self):
        self.hunter.add_target('example .com')
        assert 'example .com' not in self.hunter.targets

    def test_invalid_domain_leading_dash(self):
        self.hunter.add_target('-example.com')
        assert '-example.com' not in self.hunter.targets

    @patch.object(DiffHunter, 'scan_target')
    def test_strips_protocol(self, mock_scan):
        self.hunter.add_target('https://example.com')
        assert 'example.com' in self.hunter.targets

    @patch.object(DiffHunter, 'scan_target')
    def test_duplicate_domain(self, mock_scan):
        self.hunter.add_target('example.com')
        self.hunter.add_target('example.com')
        # Should log warning but not crash
        assert 'example.com' in self.hunter.targets


class TestTargetManagement:
    """Tests for target add/remove/list."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.hunter = DiffHunter()
        self.hunter.data_dir = Path(self.tmpdir)
        self.hunter.targets_file = self.hunter.data_dir / 'targets.json'
        self.hunter.history_dir = self.hunter.data_dir / 'history'
        self.hunter.history_dir.mkdir(exist_ok=True)
        self.hunter.alerts_file = self.hunter.data_dir / 'alerts.json'
        self.hunter.targets = {}

    @patch.object(DiffHunter, 'scan_target')
    def test_add_and_remove(self, mock_scan):
        self.hunter.add_target('example.com')
        assert 'example.com' in self.hunter.targets
        self.hunter.remove_target('example.com')
        assert 'example.com' not in self.hunter.targets

    def test_remove_nonexistent(self):
        self.hunter.remove_target('nothere.com')
        # Should not crash

    @patch.object(DiffHunter, 'scan_target')
    def test_target_persistence(self, mock_scan):
        self.hunter.add_target('example.com')
        # Reload from file
        loaded = json.loads(self.hunter.targets_file.read_text())
        assert 'example.com' in loaded


class TestDNSResolution:
    """Tests for DNS resolution helper."""

    def test_resolve_known_domain(self):
        hunter = DiffHunter()
        records = hunter.resolve_dns('google.com')
        assert 'A' in records
        assert len(records['A']) > 0

    def test_resolve_nonexistent_domain(self):
        hunter = DiffHunter()
        records = hunter.resolve_dns('this-domain-definitely-does-not-exist-12345.com')
        assert records['A'] == []


class TestAlertStorage:
    """Tests for alert save/load."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.hunter = DiffHunter()
        self.hunter.data_dir = Path(self.tmpdir)
        self.hunter.alerts_file = self.hunter.data_dir / 'alerts.json'
        self.hunter.alerts = []

    def test_save_and_load_alerts(self):
        self.hunter.alerts = [
            {'type': 'new_subdomain', 'subdomain': 'test.example.com', 'timestamp': '2026-01-01T00:00:00'}
        ]
        self.hunter.save_alerts()
        loaded = json.loads(self.hunter.alerts_file.read_text())
        assert len(loaded) == 1
        assert loaded[0]['type'] == 'new_subdomain'

    def test_load_corrupted_alerts(self):
        self.hunter.alerts_file.write_text('not valid json{{{')
        alerts = self.hunter.load_alerts()
        assert alerts == []


class TestColorDisable:
    """Tests for --no-color functionality."""

    def test_disable_colors(self):
        C.disable()
        assert C.R == ''
        assert C.G == ''
        assert C.E == ''
        # Reset for other tests
        C.R = '\033[91m'
        C.G = '\033[92m'
        C.E = '\033[0m'


class TestWebhookFormatting:
    """Tests for webhook message construction."""

    def test_webhook_no_url_noop(self):
        hunter = DiffHunter()
        hunter.webhook_url = None
        # Should not raise
        hunter.send_webhook([{'type': 'new_subdomain', 'subdomain': 'test.com'}])

    def test_webhook_empty_changes_noop(self):
        hunter = DiffHunter(webhook_url='https://example.com/hook')
        # Should not raise
        hunter.send_webhook([])


class TestConfig:
    """Tests for config persistence."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.hunter = DiffHunter()
        self.hunter.data_dir = Path(self.tmpdir)
        self.hunter.config_file = self.hunter.data_dir / 'config.json'

    def test_save_and_load_config(self):
        self.hunter.save_config({'webhook_url': 'https://example.com/hook'})
        config = self.hunter.load_config()
        assert config['webhook_url'] == 'https://example.com/hook'

    def test_load_missing_config(self):
        config = self.hunter.load_config()
        assert config == {}
