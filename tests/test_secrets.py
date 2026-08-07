"""Tests for gw2aws.secrets."""

from __future__ import annotations

import subprocess

import pytest

from gw2aws import secrets


def test_is_op_reference():
    assert secrets.is_op_reference("op://vault/item/field")
    assert not secrets.is_op_reference("plain-value")
    assert not secrets.is_op_reference("")


def test_resolve_secret_passthrough_for_plain_value():
    assert secrets.resolve_secret("plain-value") == "plain-value"
    assert secrets.resolve_secret("") == ""


def test_resolve_secret_runs_op_read(monkeypatch):
    called = {}

    def fake_which(name):
        return "/usr/bin/op"

    def fake_run(cmd, **kwargs):
        called["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="s3cr3t\n", stderr="")

    monkeypatch.setattr(secrets.shutil, "which", fake_which)
    monkeypatch.setattr(secrets.subprocess, "run", fake_run)

    assert secrets.resolve_secret("op://vault/item/field") == "s3cr3t"
    assert called["cmd"] == ["op", "read", "op://vault/item/field"]


def test_resolve_secret_missing_cli_raises(monkeypatch):
    monkeypatch.setattr(secrets.shutil, "which", lambda _name: None)
    with pytest.raises(ValueError, match="op` CLI is not installed"):
        secrets.resolve_secret("op://vault/item/field")


def test_resolve_secret_op_failure_raises(monkeypatch):
    monkeypatch.setattr(secrets.shutil, "which", lambda _name: "/usr/bin/op")

    def fake_run(cmd, **kwargs):
        raise subprocess.CalledProcessError(1, cmd, output="", stderr="not found")

    monkeypatch.setattr(secrets.subprocess, "run", fake_run)
    with pytest.raises(ValueError, match="Failed to resolve 1Password reference"):
        secrets.resolve_secret("op://vault/item/missing")
