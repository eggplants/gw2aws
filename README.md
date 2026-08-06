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
mise use -g pipx:gw2aws@<pypi version>

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

aws --profile myprofile sts get-caller-identity
```

## References

- <https://github.com/Versent/saml2aws>
- <https://aws.amazon.com/jp/blogs/security/how-to-implement-a-general-solution-for-federated-apicli-access-using-saml-2-0/>
