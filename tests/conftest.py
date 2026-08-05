"""Shared test helpers."""

from __future__ import annotations

import base64


def build_saml_assertion(
    roles: list[str] | None = None,
    session_duration: int | None = None,
    *,
    destination: str = "https://signin.aws.amazon.com/saml",
) -> str:
    """Build a base64-encoded SAML Response with the AWS Role/SessionDuration attrs."""
    role_attr_values = "".join(f"<saml:AttributeValue>{value}</saml:AttributeValue>" for value in (roles or []))
    duration_attr = ""
    if session_duration is not None:
        duration_attr = (
            '<saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/SessionDuration">'
            f"<saml:AttributeValue>{session_duration}</saml:AttributeValue>"
            "</saml:Attribute>"
        )
    xml = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        f'Destination="{destination}">'
        '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        "<saml:AttributeStatement>"
        '<saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">'
        f"{role_attr_values}"
        "</saml:Attribute>"
        f"{duration_attr}"
        "</saml:AttributeStatement>"
        "</saml:Assertion>"
        "</samlp:Response>"
    )
    return base64.b64encode(xml.encode()).decode()
