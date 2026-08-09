"""Drive a real browser through the Google Workspace SAML login and capture
the SAMLResponse that the browser POSTs to https://signin.aws.amazon.com/saml.

This mirrors saml2aws's *browser* provider (not its googleapps HTTP-scraping
provider): the IdP hands the browser a SAML assertion, the browser POSTs it to
the AWS sign-in endpoint, and we intercept that POST to recover the assertion.
Reference: https://aws.amazon.com/blogs/security/how-to-implement-a-general-solution-for-federated-apicli-access-using-saml-2-0/
"""

from __future__ import annotations

import contextlib
import gc
import json
import logging
import random
import re
import sys
import time
import urllib.parse
from pathlib import Path
from typing import TYPE_CHECKING

import pyotp
from install_playwright import install
from playwright.sync_api import BrowserContext, Page, sync_playwright
from playwright.sync_api import Error as PWError
from playwright.sync_api import TimeoutError as PWTimeoutError

from gw2aws.config import ProfileConfig

if TYPE_CHECKING:
    from collections.abc import Iterator

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

# What Google renders when it refuses a submitted secret.
PASSWORD_REJECTED = [
    "Wrong password",
    "パスワードが正しくありません",
    "パスワードが違います",
]
TOTP_REJECTED = [
    "Wrong code",
    "Invalid code",
    "That code didn't work",
    "コードが正しくありません",
    "無効なコード",
]

# Dead ends: Google has ended the flow on its own error page, so no form is
# coming and waiting only burns the capture timeout. Google types the
# apostrophe as U+2019, but older pages use the ASCII one.
SIGNIN_REJECTED = [
    "Couldn't sign you in",
    "Couldn’t sign you in",
    "Couldn't find your Google Account",
    "Couldn’t find your Google Account",
    "ログインできませんでした",
    "アカウントが見つかりません",
]
# The "we don't trust this browser" wording, which is also what an email that
# is not a Google account ends up on.
UNTRUSTED_BROWSER_HINT = (
    "Google refused the sign-in: check that the profile's email is a real "
    "Google Workspace account, and try again with --no-headless."
)
# Advice for the rejections whose cause we recognise, keyed by page text.
REJECTION_HINTS = (
    ("browser or app may not be secure", UNTRUSTED_BROWSER_HINT),
    ("安全でない可能性があります", UNTRUSTED_BROWSER_HINT),
)

# Max iterations to steer the 2FA flow toward the TOTP challenge (each ~1s+).
# Submitting a code does not count against this: rejected secrets are retried
# without limit, since only the user knows when to stop trying.
TOTP_NAV_STEPS = 40
# How long to wait for Google's verdict on a submitted password or code.
VERDICT_TIMEOUT_MS = 15_000


# Benign messages asyncio reports while the sync Playwright connection shuts
# down; see `_quiet_playwright_teardown`.
TEARDOWN_NOISE = (
    "Task was destroyed but it is pending",
    "Future exception was never retrieved",
)


class LoginError(RuntimeError):
    pass


class _TeardownNoiseFilter(logging.Filter):
    """Drops the asyncio teardown messages Playwright's connection provokes."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        if not any(text in message for text in TEARDOWN_NOISE):
            return True
        # Only ours: the task repr names playwright's connection module, and
        # the orphaned future carries a playwright TargetClosedError.
        return "playwright" not in message and "TargetClosedError" not in message


@contextlib.contextmanager
def _quiet_playwright_teardown() -> Iterator[None]:
    """Silence the asyncio noise emitted when a sync Playwright session stops.

    `PlaywrightContextManager.__exit__` cancels the driver connection's reader
    task and closes its event loop without giving the cancellation a chance to
    settle, and any protocol call still in flight gets a `TargetClosedError`
    that nobody awaits. asyncio complains about both from `__del__` ("Task was
    destroyed but it is pending!" / "Future exception was never retrieved"),
    which lands on stderr mid-login even though the login itself succeeded.

    Those objects sit in reference cycles, so whether they are collected during
    the run, at interpreter exit, or not at all is down to GC timing -- hence
    the intermittency. Collect them explicitly while the filter is installed so
    the messages are dropped deterministically instead of leaking out later.
    """
    logger = logging.getLogger("asyncio")
    noise_filter = _TeardownNoiseFilter()
    logger.addFilter(noise_filter)
    try:
        yield
    finally:
        gc.collect()
        logger.removeFilter(noise_filter)


def is_chromium_installed() -> bool:
    """Whether the Chromium build Playwright needs is already downloaded locally."""
    with _quiet_playwright_teardown(), sync_playwright() as pw:
        return Path(pw.chromium.executable_path).exists()


def fetch_saml_response(
    config: ProfileConfig,
    password_provider: PasswordProvider,
    totp_provider: TotpProvider,
    headless: bool = False,
    storage_state_path: Path | None = None,
    *,
    ignore_saved_session: bool = False,
) -> str:
    """Run the browser login and return the base64 SAMLResponse string.

    If `storage_state_path` points to previously saved cookies, they are
    loaded into the new context so an already-authenticated Google session
    can skip straight to the SAML redirect. `ignore_saved_session` starts from
    a clean context instead, for when the stored session has gone stale.

    Either way the cookies are written back once the assertion is captured, so
    the next run gets a fresh session to reuse. A run that fails leaves the
    stored cookies as they were -- a half-finished login is not worth keeping,
    and overwriting would throw away a session that may still be good.
    """
    captured: dict[str, str] = {}

    with _quiet_playwright_teardown(), sync_playwright() as pw:
        # Ensure the Chromium browser is present (installs on first run).
        install([pw.chromium])
        browser = pw.chromium.launch(headless=headless)
        has_saved_state = storage_state_path is not None and storage_state_path.exists() and not ignore_saved_session
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
            _google_login(page, config, password_provider, totp_provider, captured)
            _wait_for_capture(page, captured)
        finally:
            # Stop dispatching page events into `on_request` before shutting
            # the browser down, so nothing new is in flight while it closes.
            page.remove_listener("request", on_request)
            if storage_state_path and "saml" in captured:
                _save_cookies(context, storage_state_path)
            # The assertion is already in hand by now (or an error is on its
            # way up); a browser that died on its own must not turn either
            # outcome into a TargetClosedError.
            with contextlib.suppress(PWError):
                context.close()
            with contextlib.suppress(PWError):
                browser.close()

    if "saml" not in captured:
        raise LoginError("Did not capture a SAMLResponse from the AWS sign-in POST.")
    return captured["saml"]


def _save_cookies(context: BrowserContext, storage_state_path: Path) -> None:
    """Persist the context's cookies for the next run's session reuse.

    Cookies only (not the full `storage_state()`): capturing localStorage would
    make Playwright open a hidden page per origin visited during the Google
    login to read it back, adding several seconds to every run. Google's
    session is carried by cookies, which is all reuse needs.
    """
    try:
        cookies = context.cookies()
    except PWError as exc:
        # A browser that died before we got here costs us only the session
        # reuse -- the SAML assertion (if captured) is still good.
        print(f"warning: could not save session cookies: {exc}", file=sys.stderr)
        return
    storage_state_path.parent.mkdir(parents=True, exist_ok=True)
    storage_state_path.write_text(json.dumps({"cookies": cookies}))
    # May contain a live Google session cookie -- keep it private.
    storage_state_path.chmod(0o600)


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
        _raise_if_rejected(page)
        page.wait_for_timeout(500)
        waited += 500


def _google_login(
    page: Page,
    config: ProfileConfig,
    password_provider: PasswordProvider,
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
    _fill_password(page, password_provider, captured)
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
        _raise_if_rejected(page)
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


def _fill_password(page: Page, password_provider: PasswordProvider, captured: dict[str, str]) -> None:
    """Answer the password challenge, re-prompting for as long as Google refuses.

    A wrong password leaves us on the same form, and returning at that point
    used to send the caller off hunting for a 2FA challenge that never comes --
    the login then died on the misleading "could not reach the TOTP challenge".
    """
    password_input = page.locator("input[type='password']")
    attempts = 0
    # False once the form is gone (accepted, or satisfied by a reused session)
    # or the assertion arrived without one.
    while _wait_visible_or_captured(page, password_input, captured, STEP_TIMEOUT_MS):
        attempts += 1
        _submit_secret(page, password_input, password_provider.password(), "#passwordNext")
        if _challenge_cleared(page, password_input, captured, PASSWORD_REJECTED):
            return
        print(f"Google rejected the password (attempt {attempts}); trying again.", file=sys.stderr)


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

    A rejected code puts us back on the same challenge, so each submission is
    followed through to its verdict and retried for as long as Google keeps
    asking -- a prompted provider asks the user again every round, which is the
    whole point of noticing the rejection instead of waiting out the
    SAMLResponse timeout. Only the *steering* is bounded (`TOTP_NAV_STEPS`);
    retries are not, so `Ctrl-C` is what ends a hopeless one.
    """
    totp_input = page.locator(TOTP_INPUT_SELECTOR)
    attempts = 0
    nav_steps = 0

    while nav_steps < TOTP_NAV_STEPS:
        if "saml" in captured:
            return

        if _is_visible(totp_input):
            if attempts:
                _wait_for_fresh_code(page, totp_provider)
            attempts += 1
            _submit_secret(page, totp_input, totp_provider.code(), "#totpNext")
            if _challenge_cleared(page, totp_input, captured, TOTP_REJECTED):
                return
            # Retrying does not eat into the navigation budget: we are on the
            # right page already, just with the wrong code.
            print(f"Google rejected the TOTP code (attempt {attempts}); trying again.", file=sys.stderr)
            continue

        nav_steps += 1
        _raise_if_rejected(page)

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


def _submit_secret(page: Page, field, secret: str, next_selector: str) -> None:
    """Type `secret` into `field` and submit it."""
    # A rejected attempt leaves its text in the field; typing would append.
    with contextlib.suppress(PWTimeoutError, PWError):
        field.first.fill("")
    _human_type(page, field, secret)
    _click_next(page, next_selector)


def _challenge_cleared(page: Page, field, captured: dict[str, str], rejected_texts: list[str]) -> bool:
    """Follow a submitted secret to its verdict: True once Google moves on.

    Google answers a wrong password or code by re-rendering the same form with
    an error, so "the field is still there" is the signal to retry. The error
    text is only used to fail fast -- the timeout decides on its own if the
    wording has drifted, since sitting on the form is a rejection either way.
    """
    waited = 0
    while waited < VERDICT_TIMEOUT_MS:
        if "saml" in captured:
            return True
        if _any_visible(page, rejected_texts):
            return False
        if not _is_visible(field):
            return True
        page.wait_for_timeout(POLL_INTERVAL_MS)
        waited += POLL_INTERVAL_MS
    return False


def _wait_for_fresh_code(page: Page, totp_provider: TotpProvider) -> None:
    """Hold off until the provider can produce a code it has not handed out yet."""
    remaining_ms = int(totp_provider.seconds_until_new_code() * 1000)
    if remaining_ms <= 0:
        return
    print(f"Waiting {remaining_ms // 1000 + 1}s for the next TOTP code ...", file=sys.stderr)
    page.wait_for_timeout(remaining_ms)


def _any_visible(page: Page, texts: list[str]) -> bool:
    """Whether any of `texts` is currently rendered on the page."""
    return any(_is_visible(page.get_by_text(text, exact=False)) for text in texts)


def _raise_if_rejected(page: Page) -> None:
    """Stop the login as soon as Google lands on one of its dead-end pages.

    A bad email (or a browser Google decides not to trust) ends on an error
    page with no form on it. Every wait in this module polls through here so
    that case fails immediately with what the page says, instead of running out
    the selector and SAMLResponse timeouts and then blaming the TOTP step.
    """
    if not _any_visible(page, SIGNIN_REJECTED):
        return
    detail = _page_summary(page)
    for needle, hint in REJECTION_HINTS:
        if needle in detail:
            msg = f"{hint} Google said: {detail}" if detail else hint
            raise LoginError(msg)
    raise LoginError(f"Google stopped the sign-in: {detail}" if detail else "Google stopped the sign-in.")


def _page_summary(page: Page, lines: int = 3) -> str:
    """The first few lines of the page's main content, for error messages."""
    with contextlib.suppress(PWTimeoutError, PWError):
        text = page.locator("main").first.inner_text()
        visible = [line.strip() for line in text.splitlines() if line.strip()]
        if visible:
            return " / ".join(visible[:lines])
    return ""


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


class PasswordProvider:
    """Yields the Google password: the configured one first, then prompts.

    The configured password is handed out once. Google refusing it means it is
    wrong (or has been rotated), so every retry asks the user instead of
    resubmitting the same string forever. Prompting is lazy, so a run that
    reuses a stored session -- and never sees the password form -- never asks.
    """

    def __init__(self, password: str = "", prompt=None):
        self._configured = password
        self._prompt = prompt
        self._issued = False

    def password(self) -> str:
        if self._configured and not self._issued:
            self._issued = True
            return self._configured
        if self._prompt is None:
            msg = (
                "The configured Google password was rejected and no prompt is available."
                if self._issued
                else "No Google password configured and no prompt available."
            )
            raise LoginError(msg)
        self._issued = True
        return self._prompt()


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
        self._issued = ""

    def code(self) -> str:
        if self._totp is not None:
            self._issued = self._totp.now()
        elif self._prompt is None:
            raise LoginError("No TOTP URL configured and no prompt available.")
        else:
            self._issued = self._prompt()
        return self._issued

    def seconds_until_new_code(self) -> float:
        """How long until this provider can yield a code it has not issued yet.

        A URL-derived code is fixed for its time step, so resubmitting within
        the same window replays a code Google has already refused. A prompted
        code comes from a human who can just read the next one, and a rolled-over
        window needs no wait either.
        """
        if self._totp is None or self._totp.now() != self._issued:
            return 0.0
        return self._totp.interval - (time.time() % self._totp.interval)
