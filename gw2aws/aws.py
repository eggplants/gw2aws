"""Parse AWS roles from a SAML assertion and exchange it for STS credentials."""

from __future__ import annotations

import base64
import configparser
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree

import boto3

ROLE_ATTR = "https://aws.amazon.com/SAML/Attributes/Role"
SESSION_DURATION_ATTR = "https://aws.amazon.com/SAML/Attributes/SessionDuration"


@dataclass
class AWSRole:
    role_arn: str
    principal_arn: str

    @property
    def name(self) -> str:
        # arn:aws:iam::123456789012:role/Foo -> 123456789012 / Foo
        try:
            account = self.role_arn.split(":")[4]
            role = self.role_arn.split(":role/", 1)[1]
            return f"{account} / {role}"
        except (IndexError, ValueError):
            return self.role_arn


def _decode(saml_assertion: str) -> bytes:
    return base64.b64decode(saml_assertion)


def extract_roles(saml_assertion: str) -> list[AWSRole]:
    """Extract the AWS role attribute values from a base64 SAML assertion."""
    root = ElementTree.fromstring(_decode(saml_assertion))
    roles: list[AWSRole] = []
    # Namespace-agnostic search: match on the local element name.
    for attribute in root.iter():
        if not attribute.tag.endswith("}Attribute") and not attribute.tag.endswith("Attribute"):
            continue
        if attribute.get("Name") != ROLE_ATTR:
            continue
        for value in list(attribute):
            text = (value.text or "").strip()
            if text:
                roles.append(_parse_role(text))
    return roles


def _parse_role(value: str) -> AWSRole:
    parts = [p.strip() for p in value.split(",")]
    role_arn = ""
    principal_arn = ""
    for part in parts:
        if ":saml-provider/" in part:
            principal_arn = part
        elif ":role/" in part:
            role_arn = part
    if not role_arn or not principal_arn:
        raise ValueError(f"Malformed SAML role attribute value: {value!r}")
    return AWSRole(role_arn=role_arn, principal_arn=principal_arn)


def extract_session_duration(saml_assertion: str, default: int) -> int:
    root = ElementTree.fromstring(_decode(saml_assertion))
    for attribute in root.iter():
        if attribute.get("Name") != SESSION_DURATION_ATTR:
            continue
        for value in list(attribute):
            text = (value.text or "").strip()
            if text.isdigit():
                return int(text)
    return default


@dataclass
class AWSCredentials:
    access_key_id: str
    secret_access_key: str
    session_token: str
    principal_arn: str
    expiration: datetime
    region: str


def assume_role(
    role: AWSRole,
    saml_assertion: str,
    region: str,
    duration_seconds: int,
) -> AWSCredentials:
    """Call sts:AssumeRoleWithSAML (an unauthenticated call) to obtain credentials."""
    sts = boto3.client("sts", region_name=region)
    resp = sts.assume_role_with_saml(
        RoleArn=role.role_arn,
        PrincipalArn=role.principal_arn,
        SAMLAssertion=saml_assertion,
        DurationSeconds=duration_seconds,
    )
    creds = resp["Credentials"]
    return AWSCredentials(
        access_key_id=creds["AccessKeyId"],
        secret_access_key=creds["SecretAccessKey"],
        session_token=creds["SessionToken"],
        principal_arn=resp["AssumedRoleUser"]["Arn"],
        expiration=creds["Expiration"],
        region=region,
    )


def save_credentials(profile: str, creds: AWSCredentials) -> Path:
    """Write credentials into ~/.aws/credentials under the given profile section."""
    path = Path.home() / ".aws" / "credentials"
    path.parent.mkdir(parents=True, exist_ok=True)

    parser = configparser.RawConfigParser()
    if path.exists():
        parser.read(path)

    # Rewrite the section from scratch so stale keys from a previous login do
    # not linger. In particular botocore reads `aws_security_token` *before*
    # `aws_session_token`, so a leftover legacy token would be paired with our
    # fresh access key and fail with InvalidClientTokenId.
    if parser.has_section(profile):
        parser.remove_section(profile)
    parser.add_section(profile)
    parser.set(profile, "aws_access_key_id", creds.access_key_id)
    parser.set(profile, "aws_secret_access_key", creds.secret_access_key)
    parser.set(profile, "aws_session_token", creds.session_token)
    # Legacy alias kept in sync for older tooling that reads it.
    parser.set(profile, "aws_security_token", creds.session_token)
    parser.set(profile, "region", creds.region)
    parser.set(profile, "x_principal_arn", creds.principal_arn)
    parser.set(profile, "x_security_token_expires", creds.expiration.isoformat())

    with path.open("w", encoding="utf-8") as fp:
        parser.write(fp)
    path.chmod(0o600)
    return path
