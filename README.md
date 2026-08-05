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

## Install

```bash
pipx install gw2aws
# or
pip install gw2aws
```

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
