"""Tests for gw2aws.aws."""

from __future__ import annotations

import configparser
import stat
from datetime import datetime, timezone

import pytest

from gw2aws import aws
from tests.conftest import build_saml_assertion

ADMIN = "arn:aws:iam::123456789012:role/Admin"
READONLY = "arn:aws:iam::123456789012:role/ReadOnly"
PROVIDER = "arn:aws:iam::123456789012:saml-provider/Google"


def test_extract_roles_handles_both_arn_orderings():
    assertion = build_saml_assertion(
        roles=[f"{PROVIDER},{ADMIN}", f"{READONLY},{PROVIDER}"],
    )
    roles = aws.extract_roles(assertion)
    assert len(roles) == 2
    assert roles[0] == aws.AWSRole(role_arn=ADMIN, principal_arn=PROVIDER)
    assert roles[1] == aws.AWSRole(role_arn=READONLY, principal_arn=PROVIDER)


def test_extract_roles_empty_when_no_role_values():
    assert aws.extract_roles(build_saml_assertion(roles=[])) == []


def test_parse_role_rejects_missing_principal():
    with pytest.raises(ValueError, match="Malformed SAML role"):
        aws._parse_role(ADMIN)


def test_aws_role_name_formats_account_and_role():
    assert aws.AWSRole(role_arn=ADMIN, principal_arn=PROVIDER).name == "123456789012 / Admin"


def test_extract_session_duration_prefers_attribute():
    assertion = build_saml_assertion(roles=[f"{PROVIDER},{ADMIN}"], session_duration=7200)
    assert aws.extract_session_duration(assertion, default=3600) == 7200


def test_extract_session_duration_falls_back_to_default():
    assertion = build_saml_assertion(roles=[f"{PROVIDER},{ADMIN}"])
    assert aws.extract_session_duration(assertion, default=3600) == 3600


def _creds() -> aws.AWSCredentials:
    return aws.AWSCredentials(
        access_key_id="ASIANEW",
        secret_access_key="SECRETNEW",
        session_token="TOKENNEW",
        principal_arn="arn:aws:sts::1:assumed-role/Admin/user",
        expiration=datetime(2030, 1, 1, tzinfo=timezone.utc),
        region="ap-northeast-1",
    )


def test_save_credentials_writes_both_token_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    path = aws.save_credentials("prof", _creds())

    parser = configparser.RawConfigParser()
    parser.read(path)
    assert parser.get("prof", "aws_access_key_id") == "ASIANEW"
    # Both the modern and legacy token keys are written in sync (botocore reads
    # aws_security_token first).
    assert parser.get("prof", "aws_session_token") == "TOKENNEW"
    assert parser.get("prof", "aws_security_token") == "TOKENNEW"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_save_credentials_removes_stale_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    creds_path = tmp_path / ".aws" / "credentials"
    creds_path.parent.mkdir(parents=True)
    creds_path.write_text(
        "[prof]\naws_access_key_id = ASIAOLD\naws_security_token = STALE\nleftover_key = junk\n",
    )

    aws.save_credentials("prof", _creds())

    parser = configparser.RawConfigParser()
    parser.read(creds_path)
    assert parser.get("prof", "aws_access_key_id") == "ASIANEW"
    assert parser.get("prof", "aws_security_token") == "TOKENNEW"
    assert not parser.has_option("prof", "leftover_key")


def test_save_credentials_preserves_other_profiles(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    creds_path = tmp_path / ".aws" / "credentials"
    creds_path.parent.mkdir(parents=True)
    creds_path.write_text("[other]\naws_access_key_id = KEEP\n")

    aws.save_credentials("prof", _creds())

    parser = configparser.RawConfigParser()
    parser.read(creds_path)
    assert parser.get("other", "aws_access_key_id") == "KEEP"
    assert parser.has_section("prof")


def test_assume_role_maps_sts_response(monkeypatch):
    captured = {}

    class FakeSTS:
        def assume_role_with_saml(self, **kwargs):
            captured.update(kwargs)
            return {
                "Credentials": {
                    "AccessKeyId": "ASIA",
                    "SecretAccessKey": "SECRET",
                    "SessionToken": "TOKEN",
                    "Expiration": datetime(2030, 1, 1, tzinfo=timezone.utc),
                },
                "AssumedRoleUser": {"Arn": "arn:aws:sts::1:assumed-role/Admin/user"},
            }

    monkeypatch.setattr(aws.boto3, "client", lambda service, region_name: FakeSTS())

    role = aws.AWSRole(role_arn=ADMIN, principal_arn=PROVIDER)
    creds = aws.assume_role(role, "SAMLB64", region="us-east-1", duration_seconds=3600)

    assert captured["RoleArn"] == ADMIN
    assert captured["PrincipalArn"] == PROVIDER
    assert captured["SAMLAssertion"] == "SAMLB64"
    assert captured["DurationSeconds"] == 3600
    assert creds.access_key_id == "ASIA"
    assert creds.principal_arn == "arn:aws:sts::1:assumed-role/Admin/user"
    assert creds.region == "us-east-1"
