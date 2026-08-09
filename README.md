# gw2aws

[![PyPI version](
  <https://badge.fury.io/py/gw2aws.svg>
  )](
  <https://badge.fury.io/py/gw2aws>
) [![CI](
  <https://github.com/eggplants/gw2aws/actions/workflows/ci.yml/badge.svg>
  )](
  <https://github.com/eggplants/gw2aws/actions/workflows/ci.yml>
)

SAML login to AWS via Google Workspace using Playwright.

Based on the behavior of the [`saml2aws`](https://github.com/Versent/saml2aws) Browser provider, `gw2aws` enables automated authentication for Google Workspace SSO.

## Install

```bash
# mise
mise use -g pipx:gw2aws

# pipx
pipx install gw2aws

# pip
pip install gw2aws
```

## Requirements

You must have a Google Workspace account with [2FA enabled and TOTP registered as an authentication method](https://support.google.com/accounts/answer/1066447).

## Usage

```bash
gw2aws configure --profile myprofile

gw2aws login --profile myprofile
gw2aws login --profile myprofile --no-headless
gw2aws login --profile myprofile --force

aws --profile myprofile sts get-caller-identity
```

## Configuration

`gw2aws configure` writes a per-profile JSON file. Each profile holds:

| Field | Description | `op://` ok? |
| --- | --- | :---: |
| `url` | Google IdP-initiated SSO (SAML) login URL | |
| `email` | Google Workspace account email | ✅ |
| `password` | Google password (optional; prompted at login if empty) | ✅ |
| `totp_url` | `otpauth://` URL for TOTP (optional; prompted at login if empty) | ✅ |
| `region` | AWS region for the STS call (default `us-east-1`) | |
| `role_arn` | Role to auto-select (optional; prompted if empty and multiple roles) | |
| `session_duration` | STS credential lifetime in seconds (default `3600`) | |
| `save_session_cookie` | Persist the Google session cookie to skip login on reuse (`--force` bypasses it) | |

### Storage locations

- Profile config: `~/.config/gw2aws/<profile>.json` (mode `0600`; honors `GW2AWS_CONFIG_DIR` / `XDG_CONFIG_HOME`)
- Session cookie: `~/.config/gw2aws/<profile>.storage_state.json`
- AWS credentials: `~/.aws/credentials` (written under the profile name on login)

### 1Password references

`email`, `password`, and `totp_url` can be set to a 1Password secret reference
(`op://vault/item/field`) instead of the raw value. At login time they are
resolved via `op read`, so nothing secret is stored in the profile JSON. This
requires the [1Password CLI](https://developer.1password.com/docs/cli/) to be
installed and signed in.

## References

- <https://github.com/Versent/saml2aws>
- <https://aws.amazon.com/jp/blogs/security/how-to-implement-a-general-solution-for-federated-apicli-access-using-saml-2-0/>
