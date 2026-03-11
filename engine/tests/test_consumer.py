"""Phase 1 — Consumer and events API tests."""
import hashlib
import json
from pathlib import Path

import pytest

# Add engine root to path so we can import engine.consumer
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.consumer import _parse_event, _compute_sha256


# ── Sample Beelzebub events ────────────────────────────

SAMPLE_SSH_EVENT = json.dumps({
    "DateTime": "2026-03-11T05:32:16Z",
    "RemoteAddr": "192.168.97.1:35074",
    "Protocol": "SSH",
    "Command": "ls -la",
    "CommandOutput": "total 0\ndrwxr-xr-x 2 root root 40 Mar 11 05:32 .",
    "Status": "Stateless",
    "Msg": "New command received",
    "ID": "34b664bd-abcd-1234-5678-abcdef012345",
    "User": "root",
    "Password": "root",
    "Client": "SSH-2.0-OpenSSH_10.0",
    "SourceIp": "192.168.97.1",
    "SourcePort": "35074",
}).encode()

SAMPLE_HTTP_EVENT = json.dumps({
    "DateTime": "2026-03-11T06:00:00Z",
    "RemoteAddr": "10.0.0.5:44120",
    "Protocol": "HTTP",
    "Command": "GET /wp-admin",
    "Status": "Stateless",
    "Msg": "HTTP request received",
    "ID": "http-session-001",
    "SourceIp": "10.0.0.5",
    "SourcePort": "44120",
}).encode()

MALFORMED_EVENT = b"this is not json{{"

NO_IP_EVENT = json.dumps({
    "DateTime": "2026-03-11T06:00:00Z",
    "Protocol": "TCP",
    "Command": "test",
}).encode()


# ── SHA256 Tests ────────────────────────────────────────

def test_sha256_deterministic():
    """Chain of custody: same payload → same hash."""
    h1 = _compute_sha256(SAMPLE_SSH_EVENT)
    h2 = _compute_sha256(SAMPLE_SSH_EVENT)
    assert h1 == h2
    assert len(h1) == 64  # SHA256 hex length


def test_sha256_different_payloads():
    """Different payloads produce different hashes."""
    h1 = _compute_sha256(SAMPLE_SSH_EVENT)
    h2 = _compute_sha256(SAMPLE_HTTP_EVENT)
    assert h1 != h2


def test_sha256_matches_stdlib():
    """Verify our hash matches hashlib directly."""
    expected = hashlib.sha256(SAMPLE_SSH_EVENT).hexdigest()
    assert _compute_sha256(SAMPLE_SSH_EVENT) == expected


# ── Event Parsing Tests ─────────────────────────────────

def test_parse_ssh_event():
    """Parse a standard SSH honeypot event."""
    result = _parse_event(SAMPLE_SSH_EVENT)
    assert result is not None
    assert result["source_ip"] == "192.168.97.1"
    assert result["source_port"] == 35074
    assert result["protocol"] == "SSH"
    assert result["dest_port"] == 22
    assert result["session_id"] == "34b664bd-abcd-1234-5678-abcdef012345"
    assert result["command"] == "ls -la"
    assert result["sha256"] == _compute_sha256(SAMPLE_SSH_EVENT)


def test_parse_http_event():
    """Parse an HTTP honeypot event."""
    result = _parse_event(SAMPLE_HTTP_EVENT)
    assert result is not None
    assert result["source_ip"] == "10.0.0.5"
    assert result["protocol"] == "HTTP"
    assert result["dest_port"] == 80
    assert result["command"] == "GET /wp-admin"


def test_parse_malformed_json():
    """Malformed JSON returns None (skip, don't crash)."""
    result = _parse_event(MALFORMED_EVENT)
    assert result is None


def test_parse_event_without_ip():
    """Event without source IP is skipped."""
    result = _parse_event(NO_IP_EVENT)
    assert result is None


def test_parse_timestamp():
    """ISO 8601 timestamp parsed correctly."""
    result = _parse_event(SAMPLE_SSH_EVENT)
    assert result["timestamp"].year == 2026
    assert result["timestamp"].month == 3
    assert result["timestamp"].day == 11


def test_payload_contains_raw():
    """Payload JSONB preserves the full raw event."""
    result = _parse_event(SAMPLE_SSH_EVENT)
    payload = json.loads(result["payload"])
    assert payload["User"] == "root"
    assert payload["Password"] == "root"
    assert payload["Client"] == "SSH-2.0-OpenSSH_10.0"


# ── Constraint Tests ────────────────────────────────────

def test_main_under_500_lines():
    """C2: main.py must stay under 500 lines."""
    main_py = Path(__file__).parent.parent / "main.py"
    lines = len(main_py.read_text().splitlines())
    assert lines < 500, f"main.py has {lines} lines (limit: 500)"


def test_consumer_module_exists():
    """Consumer module is importable."""
    from engine.consumer import consume_events
    assert callable(consume_events)


def test_no_pandas():
    """C1: No pandas in engine code."""
    banned = ["im" + "port pan" + "das", "from pan" + "das"]
    engine_dir = Path(__file__).parent.parent
    for py_file in engine_dir.rglob("*.py"):
        if "test_" in py_file.name:
            continue
        content = py_file.read_text()
        for pattern in banned:
            assert pattern not in content, f"pandas found in {py_file}"


# ── Service Config Tests ───────────────────────────────

def test_sensor_configs_valid_yaml():
    """All service example YAMLs are valid."""
    import yaml
    services_dir = Path(__file__).parent.parent.parent / "beelzebub" / "configurations" / "services.example"
    yamls = list(services_dir.glob("*.yaml"))
    assert len(yamls) >= 3, f"Expected ≥3 sensor configs, found {len(yamls)}"
    for yf in yamls:
        data = yaml.safe_load(yf.read_text())
        assert "protocol" in data, f"{yf.name} missing protocol"
        assert "address" in data, f"{yf.name} missing address"


def test_sensor_configs_no_real_keys():
    """Example configs must NOT contain real API keys."""
    services_dir = Path(__file__).parent.parent.parent / "beelzebub" / "configurations" / "services.example"
    for yf in services_dir.glob("*.yaml"):
        content = yf.read_text()
        assert "sk-proj-" not in content, f"Real API key found in {yf.name}!"
