"""Drive a real browser through the Google Workspace SAML login and capture
the SAMLResponse that the browser POSTs to https://signin.aws.amazon.com/saml.

This mirrors saml2aws's *browser* provider (not its googleapps HTTP-scraping
provider): the IdP hands the browser a SAML assertion, the browser POSTs it to
the AWS sign-in endpoint, and we intercept that POST to recover the assertion.
Reference: https://aws.amazon.com/blogs/security/how-to-implement-a-general-solution-for-federated-apicli-access-using-saml-2-0/
"""

from __future__ import annotations

import json
import random
import re
import urllib.parse
from pathlib import Path

import pyotp
from install_playwright import install
from playwright.sync_api import Error as PWError
from playwright.sync_api import Page, sync_playwright
from playwright.sync_api import TimeoutError as PWTimeoutError

from gw2aws.config import ProfileConfig

# https://docs.aws.amazon.com/general/latest/gr/signin-service.html
SIGNIN_RE = re.compile(r"https://((.*\.)?signin\.(aws\.amazon\.com|amazonaws-us-gov\.com|amazonaws\.cn))/saml")

DEFAULT_TIMEOUT_MS = 300_000  # 5 min overall wait for the SAMLResponse
STEP_TIMEOUT_MS = 30_000  # per-selector wait
POLL_INTERVAL_MS = 200  # step size when polling a selector against STEP_TIMEOUT_MS

# Human-like randomised waits (milliseconds): applied between keystrokes and
# before button actions to avoid an obviously robotic input cadence.
TYPE_DELAY_MS = (200, 750)  # ~80-250 chars/min, human typing speed
CLICK_DELAY_MS = (500, 1800)

# Localised text fragments Google uses. English is forced via `hl=en`, but we
# keep Japanese fallbacks in case the org locale overrides it.
TRY_ANOTHER_WAY = ["Try another way", "他の方法を試す", "別の方法を試す"]
AUTHENTICATOR_OPTION = [
    "Get a verification code from the Google Authenticator",
    "Google Authenticator",
    "認証システム",
]

TOTP_INPUT_SELECTOR = "input#totpPin, input[name='totpPin'], input[name='Pin']"

# Max iterations to steer the 2FA flow toward the TOTP challenge (each ~1s+).
TOTP_NAV_STEPS = 40


class LoginError(RuntimeError):
    pass


def fetch_saml_response(
    config: ProfileConfig,
    password: str,
    totp_provider: TotpProvider,
    headless: bool = False,
    storage_state_path: Path | None = None,
) -> str:
    """Run the browser login and return the base64 SAMLResponse string.

    If `storage_state_path` points to previously saved cookies, they are
    loaded into the new context so an already-authenticated Google session
    can skip straight to the SAML redirect. The (possibly refreshed) cookies
    are saved back afterwards so the next run can reuse them too.
    """
    captured: dict[str, str] = {}

    with sync_playwright() as pw:
        # Ensure the Chromium browser is present (installs on first run).
        install([pw.chromium])
        browser = pw.chromium.launch(headless=headless)
        has_saved_state = storage_state_path is not None and storage_state_path.exists()
        context = browser.new_context(storage_state=str(storage_state_path) if has_saved_state else None)
        page = context.new_page()

        def on_request(request) -> None:
            if request.method == "POST" and SIGNIN_RE.match(request.url):
                data = request.post_data
                if not data:
                    return
                values = urllib.parse.parse_qs(data)
                if "SAMLResponse" in values:
                    captured["saml"] = values["SAMLResponse"][0]

        page.on("request", on_request)

        try:
            page.goto(_localise(config.url))
            _google_login(page, config, password, totp_provider, captured)
            _wait_for_capture(page, captured)
        finally:
            if storage_state_path:
                # Cookies only (not the full storage_state()): capturing
                # localStorage would make Playwright open a hidden page per
                # origin visited during the Google login to read it back,
                # adding several seconds to every run. Google's session is
                # carried by cookies, which is all reuse needs.
                storage_state_path.parent.mkdir(parents=True, exist_ok=True)
                storage_state_path.write_text(json.dumps({"cookies": context.cookies()}))
                # May contain a live Google session cookie -- keep it private.
                storage_state_path.chmod(0o600)
            context.close()
            browser.close()

    if "saml" not in captured:
        raise LoginError("Did not capture a SAMLResponse from the AWS sign-in POST.")
    return captured["saml"]


def _localise(url: str) -> str:
    """Force the Google UI to English so selectors are stable."""
    parts = urllib.parse.urlsplit(url)
    query = dict(urllib.parse.parse_qsl(parts.query))
    query.setdefault("hl", "en")
    new_query = urllib.parse.urlencode(query)
    return urllib.parse.urlunsplit(parts._replace(query=new_query))


def _wait_for_capture(page: Page, captured: dict) -> None:
    waited = 0
    while "saml" not in captured and waited < DEFAULT_TIMEOUT_MS:
        page.wait_for_timeout(500)
        waited += 500


def _google_login(
    page: Page,
    config: ProfileConfig,
    password: str,
    totp_provider: TotpProvider,
    captured: dict[str, str],
) -> None:
    # A reused storage state can make Google skip straight to the SAML
    # redirect without ever rendering the email/password/2FA forms.
    if "saml" in captured:
        return
    _fill_email(page, config.email, captured)
    if "saml" in captured:
        return
    _fill_password(page, password, captured)
    if "saml" in captured:
        return
    _handle_totp(page, totp_provider, captured)


def _wait_visible_or_captured(page: Page, locator, captured: dict[str, str], timeout_ms: int) -> bool:
    """Poll for `locator` to become visible, bailing early if `captured` fills in.

    A plain `locator.wait_for(state="visible", timeout=...)` blocks for the
    full timeout with no way to notice that a reused session already
    produced the SAMLResponse in the background (the field it's waiting for
    will simply never appear). Polling in short steps lets that case return
    almost immediately instead of burning the whole timeout.
    """
    waited = 0
    while waited < timeout_ms:
        if "saml" in captured:
            return False
        if _is_visible(locator):
            return True
        page.wait_for_timeout(POLL_INTERVAL_MS)
        waited += POLL_INTERVAL_MS
    return False


def _fill_email(page: Page, email: str, captured: dict[str, str]) -> None:
    # Google's email field is a text input (name="identifier"/id="identifierId"),
    # not type="email".
    email_input = page.locator("input#identifierId, input[name='identifier'], input[type='email']")
    if not _wait_visible_or_captured(page, email_input, captured, STEP_TIMEOUT_MS):
        # Email may already be chosen (login_hint / account chooser skipped),
        # or the SAMLResponse was already captured (reused session).
        return
    _human_type(page, email_input, email)
    _click_next(page, "#identifierNext")


def _fill_password(page: Page, password: str, captured: dict[str, str]) -> None:
    password_input = page.locator("input[type='password']")
    if not _wait_visible_or_captured(page, password_input, captured, STEP_TIMEOUT_MS):
        # Password may already be satisfied by a reused session (storage state).
        return
    _human_type(page, password_input, password)
    _click_next(page, "#passwordNext")


def _handle_totp(page: Page, totp_provider: TotpProvider, captured: dict[str, str]) -> None:
    """Reach and complete the Google Authenticator (TOTP) 2-Step Verification.

    After the password step Google may land on any of several 2FA defaults:
    a device prompt ("Check your device"), an SMS challenge, a passkey prompt
    ("Use your passkey ..."), or the TOTP field directly. We keep steering
    toward the authenticator TOTP challenge until its input field appears --
    open the method chooser via "Try another way" (never the passkey/device
    "Continue" button), pick the Google Authenticator option, and finally type
    the code. `captured` is polled so a reused session that redirects straight
    to the SAML POST (2FA fully skipped) bails out instead of looping.
    """
    totp_input = page.locator(TOTP_INPUT_SELECTOR)

    for _ in range(TOTP_NAV_STEPS):
        if "saml" in captured:
            return

        if _is_visible(totp_input):
            code = totp_provider.code()
            _human_type(page, totp_input, code)
            _click_next(page, "#totpNext")
            return

        # On the method chooser: pick the authenticator (TOTP) option.
        if _click_if_visible(page, AUTHENTICATOR_OPTION):
            page.wait_for_timeout(1_000)  # allow the TOTP page to render
            continue

        # On a different challenge (device prompt, SMS, ...): open the chooser.
        if _click_if_visible(page, TRY_ANOTHER_WAY):
            page.wait_for_timeout(1_000)  # allow the chooser to render
            continue

        # Nothing actionable yet (page still loading): wait and re-check.
        page.wait_for_timeout(1_000)

    if "saml" in captured:
        return
    raise LoginError(
        "Could not reach the Google Authenticator (TOTP) challenge: no TOTP field, "
        "authenticator option, or 'Try another way' button was found."
    )


def _click_if_visible(page: Page, texts: list[str]) -> bool:
    """Click the first currently-visible element matching any of `texts`."""
    for text in texts:
        locator = page.get_by_text(text, exact=False).first
        try:
            if locator.is_visible():
                _sleep(page, CLICK_DELAY_MS)
                locator.click(timeout=STEP_TIMEOUT_MS)
                return True
        except (PWTimeoutError, PWError):
            continue
    return False


def _is_visible(locator) -> bool:
    try:
        return locator.first.is_visible()
    except (PWTimeoutError, PWError):
        return False


def _click_next(page: Page, selector: str) -> None:
    _sleep(page, CLICK_DELAY_MS)
    button = page.locator(selector)
    try:
        if button.count() > 0:
            button.first.click(timeout=STEP_TIMEOUT_MS)
            return
    except PWTimeoutError:
        pass
    # Fallback: submit via keyboard.
    page.keyboard.press("Enter")


def _sleep(page: Page, range_ms: tuple[int, int]) -> None:
    """Wait a random duration (ms) while still pumping browser events."""
    page.wait_for_timeout(random.uniform(*range_ms))


def _human_type(page: Page, locator, text: str) -> None:
    """Type `text` one character at a time with a random pause per keystroke."""
    locator.first.click(timeout=STEP_TIMEOUT_MS)
    keyboard = page.keyboard
    for char in text:
        _sleep(page, TYPE_DELAY_MS)
        keyboard.insert_text(char)


class TotpProvider:
    """Yields TOTP codes, either derived from an otpauth URL or prompted."""

    def __init__(self, totp_url: str = "", prompt=None):
        self._totp: pyotp.TOTP | None = None
        if totp_url:
            parsed = pyotp.parse_uri(totp_url)
            if not isinstance(parsed, pyotp.TOTP):
                raise ValueError("Configured totp_url is not a TOTP otpauth:// URL.")
            self._totp = parsed
        self._prompt = prompt

    def code(self) -> str:
        if self._totp is not None:
            return self._totp.now()
        if self._prompt is None:
            raise LoginError("No TOTP URL configured and no prompt available.")
        return self._prompt()
