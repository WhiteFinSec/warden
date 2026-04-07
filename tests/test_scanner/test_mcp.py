"""Tests for Layer 2: MCP scanner."""

import json
import tempfile
from pathlib import Path

from warden.scanner.mcp_scanner import scan_mcp


def test_detects_write_tools_no_auth():
    config = {
        "mcpServers": {
            "filesystem": {
                "tools": [
                    {"name": "write_file", "description": "Write a file"},
                    {"name": "delete_file", "description": "Delete a file"},
                ]
            }
        }
    }
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "mcp.json").write_text(json.dumps(config))
        findings, _, _ = scan_mcp(Path(tmpdir))
        assert any("write tools without authentication" in f.message for f in findings)


def test_no_findings_for_authed_server():
    config = {
        "mcpServers": {
            "secure": {
                "tools": [
                    {"name": "write_file", "description": "Write a file", "inputSchema": {}},
                ],
                "auth": {"type": "bearer", "token": "env:MCP_TOKEN"}
            }
        }
    }
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "mcp.json").write_text(json.dumps(config))
        findings, _, _ = scan_mcp(Path(tmpdir))
        assert not any("without authentication" in f.message for f in findings)


def test_no_mcp_config_no_findings():
    with tempfile.TemporaryDirectory() as tmpdir:
        findings, _, _ = scan_mcp(Path(tmpdir))
        assert len(findings) == 0
