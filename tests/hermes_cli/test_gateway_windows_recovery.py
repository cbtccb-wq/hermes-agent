"""Regression coverage for localized Windows task discovery and tracked launchers."""
import csv
import io
import sys
import time
from types import SimpleNamespace

import pytest

from hermes_cli import gateway_runtime_service as service
from hermes_cli import gateway_windows
from hermes_cli.gateway_runtime_service_identity import verify_windows_task


def _installed_task(tmp_path, *, tracked=False):
    home = tmp_path / "Hermes-日本語"
    home.mkdir()
    script = home / "gateway.vbs"
    launcher = gateway_windows._build_gateway_vbs_script(sys.executable, str(home), str(home), "")
    if tracked:
        launcher = launcher.replace("Dim sh, env, existing_pp", "Dim sh, env, existing_pp, exit_code")
        prefix, command = launcher.rsplit("sh.Run ", 1)
        launcher = prefix + "exit_code = sh.Run(" + command.rstrip().removesuffix(", 0, False") + ", 0, True)\r\nWScript.Quit exit_code\r\n"
    script.write_text(launcher, encoding="utf-8", newline="")
    account, sid = r"DESKTOP\利用者", "S-1-5-21-123"
    suffix = service.service_suffix(home)
    name = "Hermes_Gateway" + ("_" + suffix if suffix else "")
    xml = gateway_windows._build_scheduled_task_xml(name, script, sid)
    # Task Scheduler elides these defaults on an actual export.
    xml = xml.replace("<RunLevel>LeastPrivilege</RunLevel>", "").replace("<Enabled>true</Enabled>", "")
    return home, script, name, account, sid, xml


@pytest.mark.platforms("windows")
@pytest.mark.parametrize("codec", ["utf-8", "cp932", "utf-16"])
@pytest.mark.parametrize("tracked", [False, True])
def test_localized_export_resolves_and_starts_only_the_verified_task(tmp_path, monkeypatch, codec, tracked):
    home, script, name, account, sid, xml = _installed_task(tmp_path, tracked=tracked)
    original = script.read_bytes()
    account_csv = io.StringIO()
    csv.writer(account_csv).writerow([account, sid])
    replies = {
        ("schtasks.exe", "/Query", "/FO", "CSV", "/NH"): f'"\\{name}","N/A","準備完了"\r\n',
        ("schtasks.exe", "/Query", "/TN", name, "/XML"): xml,
        ("whoami.exe", "/USER", "/FO", "CSV", "/NH"): account_csv.getvalue(),
        ("schtasks.exe", "/Run", "/TN", name): "",
    }
    calls = []

    def boundary(argv, deadline, *, encoding="utf-8"):
        calls.append(tuple(argv))
        raw = replies[tuple(argv)].encode(codec)
        return SimpleNamespace(returncode=0, stdout=raw if encoding is None else raw.decode(encoding))

    monkeypatch.setattr(service, "_run", boundary)
    monkeypatch.setattr(gateway_windows, "_windows_console_encodings", lambda: ("cp932",))
    found = service.discover_existing_gateway_service(home, deadline=time.monotonic() + 5)
    assert found is not None
    assert found.start_argv == ("schtasks.exe", "/Run", "/TN", name)
    service.start_existing_gateway_service(found, deadline=time.monotonic() + 5)
    assert calls.count(found.start_argv) == 1
    assert script.read_bytes() == original


@pytest.mark.platforms("windows")
@pytest.mark.parametrize("case,reason", [
    ("elevated", "service_identity_unverified"),
    ("disabled", "service_disabled"),
    ("wrong_user", "service_account_mismatch"),
    ("extra_statement", "service_identity_unverified"),
    ("wrong_exit", "service_identity_unverified"),
    ("wrong_home", "profile_mismatch"),
    ("wrong_command", "service_identity_unverified"),
])
def test_export_defaults_and_tracked_launcher_keep_identity_checks(tmp_path, case, reason):
    home, script, _name, account, sid, xml = _installed_task(tmp_path, tracked=True)
    xml_changes = {
        "elevated": ("</Principal>", "<RunLevel>HighestAvailable</RunLevel></Principal>"),
        "disabled": ("</Settings>", "<Enabled>false</Enabled></Settings>"),
        "wrong_user": (sid, "S-1-5-18"),
    }
    launcher_changes = {
        "extra_statement": ("WScript.Quit exit_code", 'WScript.Quit exit_code\nsh.Run "calc.exe", 0, False'),
        "wrong_exit": ("WScript.Quit exit_code", "WScript.Quit 0"),
        "wrong_home": (f'env.Item("HERMES_HOME") = "{home}"', f'env.Item("HERMES_HOME") = "{tmp_path / "other"}"'),
        "wrong_command": ("gateway run", "gateway status"),
    }
    if case in xml_changes:
        xml = xml.replace(*xml_changes[case])
    else:
        launcher = script.read_text(encoding="utf-8").replace(*launcher_changes[case])
        script.write_text(launcher, encoding="utf-8", newline="")
    with pytest.raises(ValueError, match=reason):
        verify_windows_task(xml, home, account, sid)


def test_decode_real_utf16_and_malformed_output():
    assert gateway_windows._decode_schtasks_output("Hermès".encode("utf-16")) == "Hermès"
    assert gateway_windows._decode_schtasks_output(b"\xff\xfe<\x00?")
