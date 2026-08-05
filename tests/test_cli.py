"""Tests for gw2aws.cli."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from gw2aws import cli, config
from gw2aws.aws import AWSRole
from gw2aws.browser import LoginError

PROVIDER = "arn:aws:iam::1:saml-provider/Google"
ADMIN = AWSRole(role_arn="arn:aws:iam::1:role/Admin", principal_arn=PROVIDER)
READONLY = AWSRole(role_arn="arn:aws:iam::1:role/ReadOnly", principal_arn=PROVIDER)


def test_resolve_role_single_role_auto_selected():
    assert cli._resolve_role([ADMIN], "") is ADMIN


def test_resolve_role_matches_configured_arn():
    assert cli._resolve_role([ADMIN, READONLY], READONLY.role_arn) is READONLY


def test_resolve_role_configured_arn_not_found_raises():
    with pytest.raises(LoginError, match="not present in assertion"):
        cli._resolve_role([ADMIN], "arn:aws:iam::1:role/Missing")


def test_resolve_role_prompts_on_multiple(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "1")
    assert cli._resolve_role([ADMIN, READONLY], "") is READONLY


def test_resolve_role_reprompts_on_invalid_choice(monkeypatch):
    answers = iter(["9", "x", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert cli._resolve_role([ADMIN, READONLY], "") is ADMIN


def test_main_reports_missing_profile(capsys, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    assert cli.main(["login", "--profile", "ghost"]) == 1
    assert "error:" in capsys.readouterr().err


def test_login_headless_defaults_true(monkeypatch):
    captured = {}
    cfg = config.ProfileConfig(url="https://x", email="a@b.com", password="pw")
    monkeypatch.setattr(config, "load", lambda _profile: cfg)
    monkeypatch.setattr(cli, "is_chromium_installed", lambda: True)
    monkeypatch.setattr(
        cli,
        "fetch_saml_response",
        lambda cfg, password, totp_provider, headless, storage_state_path=None: captured.setdefault(
            "headless", headless
        )
        or "SAML",
    )
    monkeypatch.setattr(cli.aws, "extract_roles", lambda _s: [ADMIN])
    monkeypatch.setattr(cli.aws, "extract_session_duration", lambda _s, default: default)

    class FakeCreds:
        principal_arn = "arn:aws:sts::1:assumed-role/Admin/user"
        expiration = datetime(2030, 1, 1, tzinfo=timezone.utc)

    monkeypatch.setattr(cli.aws, "assume_role", lambda *a, **k: FakeCreds())
    monkeypatch.setattr(cli.aws, "save_credentials", lambda _p, _c: "/tmp/creds")

    assert cli.main(["login", "--profile", "demo"]) == 0
    assert captured["headless"] is True
