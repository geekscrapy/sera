"""Unit tests for `sera monitor` reactive LLM log monitoring, next-step guidance, and failure diagnostics."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from typer.testing import CliRunner

from sera.cli.app import app
from sera.core.db import SeraDatabase, scrub_secret_fields
from sera.hooks.guard_dot_sera import evaluate_pre_tool_use


runner = CliRunner()


def test_secret_scrubber_redacts_tokens_secrets_and_cookies() -> None:
    scrubbed = scrub_secret_fields(
        {
            "source_type": "microsoft",
            "proxy_url": "socks5://127.0.0.1:1080",
            "access_token": "eyJ-super-secret",
            "client_secret": "shhh",
            "cookie": "sccauth=secret-cookie",
            "nested": {"hec_token": "splunk-secret", "format": "splunk_hec"},
        }
    )
    assert scrubbed["source_type"] == "microsoft"
    assert scrubbed["proxy_url"] == "socks5://127.0.0.1:1080"
    assert scrubbed["access_token"] == "[REDACTED]"
    assert scrubbed["client_secret"] == "[REDACTED]"
    assert scrubbed["cookie"] == "[REDACTED]"
    assert scrubbed["nested"]["hec_token"] == "[REDACTED]"
    assert scrubbed["nested"]["format"] == "splunk_hec"


def test_sera_monitor_wakes_up_across_pre_init_failures_and_full_onboarding(tmp_path: Path) -> None:
    ws = tmp_path / "case_reactive"

    # Hook must allow the LLM to run `sera monitor` in `run_command`
    hook_res = evaluate_pre_tool_use(
        {
            "workspacePaths": [str(ws)],
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": f".venv/bin/sera monitor --workspace {ws}"},
            },
        }
    )
    assert hook_res == {"decision": "allow"}

    # 1. Start `sera monitor` in a background thread BEFORE `sera init` has even created `.sera/`!
    monitor_holder: dict[str, dict] = {}

    def _bg_monitor_init() -> None:
        res = runner.invoke(
            app,
            ["monitor", "--workspace", str(ws), "--interval", "0.05", "--timeout", "5"],
        )
        assert res.exit_code == 0, res.output
        monitor_holder["init"] = json.loads(res.stdout)

    t = threading.Thread(target=_bg_monitor_init, daemon=True)
    t.start()
    time.sleep(0.1)

    init_res = runner.invoke(app, ["init", "--workspace", str(ws), "--skip-uv"])
    assert init_res.exit_code == 0, init_res.output
    t.join(timeout=5.0)

    init_payload = monitor_holder["init"]
    assert init_payload["matched"] is True
    assert init_payload["event"]["event_type"] == "init"
    assert init_payload["event"]["status"] == "completed"
    assert init_payload["workspace_state"]["stage"] == "needs_source"
    assert "sera source add" in init_payload["event"]["recommendation"]
    cursor = init_payload["last_seq"]

    # 2. Simulate a FAILED source setup (e.g. SOCKS5 proxy tunnel down) and verify `sera monitor --since-seq` diagnoses it
    db = SeraDatabase(ws / ".sera" / "sera.sqlite")
    db.log_activity(
        "source.add",
        "failed",
        "Failed to configure source 'default' (microsoft, mode=device-code)",
        details={"source_type": "microsoft", "proxy_url": "socks5://127.0.0.1:1080", "access_token": "do-not-leak"},
        error_message="SOCKSHTTPSConnectionPool(host='login.microsoftonline.com', port=443): Connection refused",
    )

    fail_mon = runner.invoke(
        app,
        ["monitor", "--workspace", str(ws), "--since-seq", str(cursor), "--timeout", "2"],
    )
    assert fail_mon.exit_code == 0, fail_mon.output
    fail_payload = json.loads(fail_mon.stdout)
    assert fail_payload["matched"] is True
    assert fail_payload["event"]["status"] == "failed"
    assert fail_payload["event"]["details"]["access_token"] == "[REDACTED]"
    assert "Proxy/network connection failed" in fail_payload["event"]["recommendation"]
    cursor = fail_payload["last_seq"]

    # 3. Analyst succeeds with `sera source add` -> monitor advances stage to `needs_destination`
    src_ok = runner.invoke(
        app,
        [
            "source",
            "add",
            "microsoft",
            "--auth-mode",
            "static-bearer",
            "--opt",
            "access_token=secret-bearer-val",
            "--opt",
            "tenant_id=contoso-tid",
            "--workspace",
            str(ws),
        ],
    )
    assert src_ok.exit_code == 0, src_ok.output

    src_mon = runner.invoke(
        app,
        ["monitor", "--workspace", str(ws), "--since-seq", str(cursor), "--timeout", "2"],
    )
    src_payload = json.loads(src_mon.stdout)
    assert "secret-bearer-val" not in src_mon.stdout
    assert src_payload["event"]["event_type"] == "source.add"
    assert src_payload["event"]["status"] == "completed"
    assert src_payload["workspace_state"]["stage"] == "needs_destination"
    assert "sera dest add" in src_payload["event"]["recommendation"]
    cursor = src_payload["last_seq"]

    # 4. Analyst succeeds with `sera dest add` -> monitor advances stage to `ready`
    dst_ok = runner.invoke(
        app,
        [
            "dest",
            "add",
            "jsonl",
            "--opt",
            f"output_dir={tmp_path / 'out'}",
            "--workspace",
            str(ws),
        ],
    )
    assert dst_ok.exit_code == 0, dst_ok.output

    dst_mon = runner.invoke(
        app,
        ["monitor", "--workspace", str(ws), "--since-seq", str(cursor), "--timeout", "2"],
    )
    dst_payload = json.loads(dst_mon.stdout)
    assert dst_payload["event"]["event_type"] == "dest.add"
    assert dst_payload["event"]["status"] == "completed"
    assert dst_payload["workspace_state"]["stage"] == "ready"
    assert "collect" in dst_payload["event"]["recommendation"]

    # 5. `--recent` returns full secret-scrubbed history immediately
    recent_res = runner.invoke(app, ["monitor", "--recent", "--workspace", str(ws)])
    assert recent_res.exit_code == 0
    recent_data = json.loads(recent_res.stdout)
    assert recent_data["last_seq"] == dst_payload["last_seq"]
    assert recent_data["workspace_state"]["stage"] == "ready"
