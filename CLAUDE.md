# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`gw2aws` is a CLI that logs into AWS via a Google Workspace SAML IdP using a real browser (Playwright), then exchanges the captured SAML assertion for temporary STS credentials. It reimplements the **browser-provider approach** of [saml2aws](https://github.com/Versent/saml2aws).

## Commands

Managed with [uv](https://docs.astral.sh/uv/) and orchestrated via [mise](https://mise.jdx.dev/) tasks (see `mise.toml`).

```bash
uv sync                       # install deps (use --locked in CI)
uv run gw2aws configure -p <profile>   # interactive profile setup
uv run gw2aws login -p <profile>       # login (headless by default; --no-headless to watch)

mise run pytest               # run tests (uv run pytest)
uv run pytest tests/test_x.py::test_name   # run a single test
mise run pytest-cov           # tests with coverage over gw2aws/
mise run ruff                 # format (uv format)
mise run ty                   # type-check (uvx ty check)
mise run pre-commit           # ruff + ty + pymarkdown + pyproject-fmt
mise run ci                   # pre-commit + pytest-cov
```

The Chromium browser is installed automatically on first `login` via `install-playwright`; no manual `playwright install` step is needed.

Lint config lives in `pyproject.toml`: Ruff with `lint.select = ["ALL"]` and `line-length = 120`. `main.py`/`tests` have targeted per-file ignores.

## Architecture

The login flow is a pipeline across four modules in `gw2aws/`:

1. **`config.py`** — Loads/saves per-profile JSON at `~/.config/gw2aws/<profile>.json` (mode 0600; honors `GW2AWS_CONFIG_DIR`/`XDG_CONFIG_HOME`). `ProfileConfig` holds the Google SSO `url`, `email`, optional `password`/`totp_url`, and AWS `region`/`role_arn`/`session_duration`.

2. **`browser.py`** — The core. `fetch_saml_response()` drives Playwright through the Google login and returns the base64 `SAMLResponse`. **The capture mechanism is a `page.on("request")` handler matching `SIGNIN_RE` (the AWS `signin.*/saml` endpoint)** — the browser POSTs the IdP's SAML assertion there, and we intercept that POST body rather than scraping HTML. Key behaviors to preserve when editing:
   - `hl=en` is forced on the URL so English selectors are stable (Japanese fallbacks exist in the text-constant lists).
   - Human-like input: `_human_type` types char-by-char with `TYPE_DELAY_MS` random waits; button clicks wait `CLICK_DELAY_MS`. These evade bot heuristics — keep them.
   - **2FA is always steered to Google Authenticator (TOTP).** `_handle_totp` loops (`TOTP_NAV_STEPS` iterations) prioritizing: fill TOTP field → click the authenticator option → click "Try another way". This converges to the TOTP challenge regardless of Google's default (device prompt, SMS, passkey). It never clicks the passkey/device "Continue" button.
   - `TotpProvider` yields codes from a configured `otpauth://` URL (via `pyotp`) or falls back to a CLI prompt.

3. **`aws.py`** — Parses the SAML assertion (namespace-agnostic XML walk) for the `https://aws.amazon.com/SAML/Attributes/Role` values, calls `sts:AssumeRoleWithSAML` (an unauthenticated call — no existing AWS creds needed, only a region), and writes credentials to `~/.aws/credentials`. **`save_credentials` deletes and rewrites the whole profile section** so stale keys don't linger — critical because botocore reads legacy `aws_security_token` *before* `aws_session_token`, so a leftover mismatched token causes `InvalidClientTokenId`. Both keys are written in sync.

4. **`cli.py`** — argparse entry point (`gw2aws configure|login`, both accept `-p`/`--profile`). `login` is headless by default (`--headless`/`--no-headless` via `BooleanOptionalAction`). Orchestrates: load config → prompt for missing password/TOTP → `fetch_saml_response` → `extract_roles` → resolve role (auto if one or `role_arn` set, else prompt) → `assume_role` → `save_credentials`.

## Gotchas

- Google's login DOM/wording changes often. Selector/text constants (`TRY_ANOTHER_WAY`, `AUTHENTICATOR_OPTION`, the email/password/TOTP input selectors) are the fragile surface; run with `--no-headless` to debug when login breaks.
- The email field is `type="text"` (`#identifierId` / `name="identifier"`), not `type="email"`.
- Reference: [AWS federated CLI access with SAML 2.0](https://aws.amazon.com/blogs/security/how-to-implement-a-general-solution-for-federated-apicli-access-using-saml-2-0/).
