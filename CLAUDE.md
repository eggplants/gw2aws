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
mise run build-binary         # PyInstaller standalone binary into dist/
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
   - **Password and TOTP are both retried indefinitely.** Each submission goes through `_submit_secret` (clears the field first — a refused value is still in it) and is followed to its verdict by `_challenge_cleared`: the form still being on screen after `VERDICT_TIMEOUT_MS`, or a `PASSWORD_REJECTED`/`TOTP_REJECTED` text, means Google refused it. Without this a wrong secret just stalls — a wrong password used to surface as the misleading "could not reach the TOTP challenge". `TOTP_NAV_STEPS` bounds only the steering, which is why the retry branch `continue`s without incrementing `nav_steps`.
   - **Every wait polls `_raise_if_rejected`.** When Google ends the flow on an error page (`SIGNIN_REJECTED` — a bad email typically lands on "Couldn't sign you in / This browser or app may not be secure"), no form is ever coming, so the login fails right there with the page's own text instead of timing out. Note Google writes the apostrophe as U+2019.
   - `PasswordProvider` hands out the configured password once, then prompts for every retry (resubmitting a refused password is pointless). `TotpProvider` yields codes from a configured `otpauth://` URL (via `pyotp`) or falls back to a CLI prompt; `seconds_until_new_code()` keeps a retry from replaying the URL-derived code within the same time window (Google refuses a reused code). Both prompt lazily, so a run that reuses a stored session never asks.

3. **`aws.py`** — Parses the SAML assertion (namespace-agnostic XML walk) for the `https://aws.amazon.com/SAML/Attributes/Role` values, calls `sts:AssumeRoleWithSAML` (an unauthenticated call — no existing AWS creds needed, only a region), and writes credentials to `~/.aws/credentials`. **`save_credentials` deletes and rewrites the whole profile section** so stale keys don't linger — critical because botocore reads legacy `aws_security_token` *before* `aws_session_token`, so a leftover mismatched token causes `InvalidClientTokenId`. Both keys are written in sync.

4. **`cli.py`** — argparse entry point (`gw2aws configure|login`, both accept `-p`/`--profile`). `login` always runs headless; only `--no-headless` (a `store_false` on `headless`) opts out, for debugging. `--force` passes `ignore_saved_session=True` so the stored session cookie is skipped for that run (and rewritten once the login succeeds). Orchestrates: load config → build `PasswordProvider`/`TotpProvider` (which prompt lazily, mid-login) → `fetch_saml_response` → `extract_roles` → resolve role (auto if one or `role_arn` set, else prompt) → `assume_role` → `save_credentials`.

## Packaging

`packaging/gw2aws.spec` + `packaging/entrypoint.py` freeze the CLI into a single-file binary; `.github/workflows/build-binaries.yml` builds one per OS/arch on a `v*.*.*` tag (natively per runner — PyInstaller cannot cross-compile), then creates the GitHub release. Because the repo has **immutable releases** enabled — assets are locked once a release is published — the release must be created as a `draft: true` with its assets attached, and published only afterwards (`gh release edit --draft=false`). `release.yml` therefore no longer creates the release; it runs the PyPI publish off the `release: [published]` event. Three things the spec/entrypoint exist to handle:

- Playwright has no PyInstaller hook, so the spec `collect_all`s it, and moves `driver/node` into `binaries` (only those keep the +x bit and get macOS-signed).
- `copy_metadata("gw2aws")` — `__version__` reads distribution metadata, which is not package content.
- Playwright forces `PLAYWRIGHT_BROWSERS_PATH=0` for frozen apps, which would download Chromium into PyInstaller's temp unpack dir and lose it on exit; the entrypoint points it at the normal per-user cache instead.

`Dockerfile` + the `ghcr` job in `release.yml` publish `ghcr.io/eggplants/gw2aws` on the same `release: [published]` event. The image installs from `git+https://github.com/eggplants/gw2aws@${VERSION}` (passed as a build arg from the release tag) rather than copying the build context — a git clone carries the tags that `uv-dynamic-versioning` needs, so `--version` reports the real version instead of the `0.0.0` fallback. `.dockerignore` therefore excludes everything but the Dockerfile. The image is multi-arch: the `ghcr` job matrixes over `ubuntu-latest`/`ubuntu-24.04-arm` and pushes each arch **by digest only** (`push-by-digest=true`, no tags), and `ghcr-merge` joins those digests into one tagged manifest list via `docker buildx imagetools create` — native runners rather than QEMU, matching `build-binaries.yml`, because emulating `pip install` + `playwright install chromium` is far slower than a second runner. **The `playwright install chromium` step is not redundant with the `mcr.microsoft.com/playwright/python` base image**: pip resolves whatever playwright version `playwright>=1.40` allows, which routinely outranks the base image's, and a mismatched revision makes `install([pw.chromium])` re-download Chromium inside the container on every run.

## Gotchas

- Google's login DOM/wording changes often. Selector/text constants (`TRY_ANOTHER_WAY`, `AUTHENTICATOR_OPTION`, the email/password/TOTP input selectors) are the fragile surface; run with `--no-headless` to debug when login breaks.
- The email field is `type="text"` (`#identifierId` / `name="identifier"`), not `type="email"`.
- Reference: [AWS federated CLI access with SAML 2.0](https://aws.amazon.com/blogs/security/how-to-implement-a-general-solution-for-federated-apicli-access-using-saml-2-0/).
