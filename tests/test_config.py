"""Tests for gw2aws.config."""

from __future__ import annotations

import json
import stat

import pytest

from gw2aws import config


@pytest.fixture
def cfg_dir(tmp_path, monkeypatch):
    d = tmp_path / "gw2aws"
    monkeypatch.setattr(config, "CONFIG_DIR", d)
    return d


def test_from_dict_ignores_unknown_keys():
    cfg = config.ProfileConfig.from_dict(
        {"url": "https://x", "email": "a@b.com", "bogus": "nope"},
    )
    assert cfg.url == "https://x"
    assert cfg.email == "a@b.com"
    assert not hasattr(cfg, "bogus")


def test_to_dict_drops_empty_extra():
    assert "extra" not in config.ProfileConfig(url="https://x").to_dict()


def test_save_then_load_round_trip(cfg_dir):
    cfg = config.ProfileConfig(
        url="https://x",
        email="a@b.com",
        region="ap-northeast-1",
        role_arn="arn:aws:iam::1:role/Admin",
        session_duration=7200,
    )
    path = config.save("demo", cfg)
    assert path == cfg_dir / "demo.json"

    loaded = config.load("demo")
    assert loaded.url == "https://x"
    assert loaded.region == "ap-northeast-1"
    assert loaded.role_arn == "arn:aws:iam::1:role/Admin"
    assert loaded.session_duration == 7200


def test_save_sets_0600_permissions(cfg_dir):
    path = config.save("demo", config.ProfileConfig(url="https://x", email="a@b.com"))
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_save_writes_valid_json(cfg_dir):
    config.save("demo", config.ProfileConfig(url="https://x", password="secret"))
    with (cfg_dir / "demo.json").open(encoding="utf-8") as fp:
        data = json.load(fp)
    assert data["password"] == "secret"


def test_load_missing_profile_raises(cfg_dir):
    with pytest.raises(FileNotFoundError, match="gw2aws configure"):
        config.load("does-not-exist")
