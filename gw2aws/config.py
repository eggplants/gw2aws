"""Profile configuration stored at ~/.config/gw2aws/<profile>.json."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

CONFIG_DIR = Path(
    os.environ.get("GW2AWS_CONFIG_DIR") or (Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "gw2aws")
)


@dataclass
class ProfileConfig:
    """A single AWS profile's SAML login settings."""

    # Required
    url: str = ""  # Google IdP-initiated SSO (SAML) login URL
    email: str = ""  # Google Workspace account entered on the Google login screen

    # Optional credentials -- if present the interactive prompt is skipped
    password: str = ""  # Google account password
    totp_url: str = ""  # otpauth:// URL used to derive TOTP codes

    # AWS options
    region: str = "us-east-1"  # region used for the STS AssumeRoleWithSAML call
    role_arn: str = ""  # if set, this role is auto-selected without prompting
    session_duration: int = 3600  # STS credential lifetime in seconds

    # Fields not persisted for the login itself but useful defaults
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> ProfileConfig:
        known = {f: data[f] for f in cls.__dataclass_fields__ if f in data}
        return cls(**known)

    def to_dict(self) -> dict:
        data = asdict(self)
        if not data.get("extra"):
            data.pop("extra", None)
        return data


def profile_path(profile: str) -> Path:
    return CONFIG_DIR / f"{profile}.json"


def load(profile: str) -> ProfileConfig:
    path = profile_path(profile)
    if not path.exists():
        raise FileNotFoundError(
            f"No configuration for profile '{profile}'. Run `gw2aws configure --profile {profile}` first."
        )
    with path.open(encoding="utf-8") as fp:
        return ProfileConfig.from_dict(json.load(fp))


def save(profile: str, config: ProfileConfig) -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    path = profile_path(profile)
    with path.open("w", encoding="utf-8") as fp:
        json.dump(config.to_dict(), fp, indent=2, ensure_ascii=False)
        fp.write("\n")
    # Config may contain a password / TOTP secret -- keep it private.
    path.chmod(0o600)
    return path
