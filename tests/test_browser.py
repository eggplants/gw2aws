"""Tests for gw2aws.browser (pure logic; no real browser)."""

from __future__ import annotations

import json
import logging
import urllib.parse
from typing import Any, cast

import pyotp
import pytest

from gw2aws import browser
from gw2aws.config import ProfileConfig

SECRET = "JBSWY3DPEHPK3PXP"


def test_localise_adds_hl_en():
    out = browser._localise("https://accounts.google.com/o/saml2/initsso?idpid=X")
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(out).query))
    assert query["hl"] == "en"
    assert query["idpid"] == "X"


def test_localise_keeps_existing_hl():
    out = browser._localise("https://accounts.google.com/x?hl=ja")
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(out).query))
    assert query["hl"] == "ja"


def test_totp_provider_generates_code_from_url():
    url = f"otpauth://totp/AWS:me@example.com?secret={SECRET}&issuer=AWS"
    code = browser.TotpProvider(url).code()
    assert code.isdigit()
    assert code == pyotp.TOTP(SECRET).now()


def test_totp_provider_falls_back_to_prompt():
    provider = browser.TotpProvider("", prompt=lambda: "654321")
    assert provider.code() == "654321"


def test_totp_provider_prefers_url_over_prompt():
    url = f"otpauth://totp/AWS?secret={SECRET}"
    provider = browser.TotpProvider(url, prompt=lambda: "000000")
    assert provider.code() != "000000"


def test_totp_provider_without_url_or_prompt_errors():
    with pytest.raises(browser.LoginError, match="No TOTP URL"):
        browser.TotpProvider("").code()


def test_totp_provider_rejects_non_totp_uri():
    with pytest.raises(ValueError, match="not a TOTP"):
        browser.TotpProvider(f"otpauth://hotp/AWS?secret={SECRET}&counter=0")


def _record(message: str) -> logging.LogRecord:
    return logging.LogRecord("asyncio", logging.ERROR, __file__, 0, message, None, None)


def test_teardown_filter_drops_pending_task_noise():
    message = (
        "Task was destroyed but it is pending!\n"
        "task: <Task cancelling name='Task-3' coro=<Connection.run.<locals>.init() "
        "running at /x/playwright/_impl/_connection.py:344> wait_for=<Future finished result=None>>"
    )
    assert not browser._TeardownNoiseFilter().filter(_record(message))


def test_teardown_filter_drops_orphaned_target_closed_future():
    message = (
        "Future exception was never retrieved\n"
        "future: <Future finished exception=TargetClosedError('Target page, context "
        "or browser has been closed')>"
    )
    assert not browser._TeardownNoiseFilter().filter(_record(message))


def test_teardown_filter_keeps_unrelated_asyncio_errors():
    assert browser._TeardownNoiseFilter().filter(_record("Task exception was never retrieved"))
    assert browser._TeardownNoiseFilter().filter(
        _record("Future exception was never retrieved\nfuture: <Future exception=ValueError('boom')>"),
    )


def test_quiet_playwright_teardown_removes_its_filter():
    logger = logging.getLogger("asyncio")
    before = list(logger.filters)
    with browser._quiet_playwright_teardown():
        assert any(isinstance(f, browser._TeardownNoiseFilter) for f in logger.filters)
    assert list(logger.filters) == before


def test_quiet_playwright_teardown_swallows_the_noise(caplog):
    with caplog.at_level(logging.ERROR, logger="asyncio"), browser._quiet_playwright_teardown():
        logging.getLogger("asyncio").error(
            "Task was destroyed but it is pending!\ntask: <Task coro=<...playwright/_impl/_connection.py:344>>",
        )
        logging.getLogger("asyncio").error("Something else broke")
    assert [r.getMessage() for r in caplog.records] == ["Something else broke"]


def test_save_cookies_writes_private_file(tmp_path):
    class Context:
        def cookies(self):
            return [{"name": "SID", "value": "x"}]

    path = tmp_path / "nested" / "state.json"
    browser._save_cookies(cast("Any", Context()), path)
    assert json.loads(path.read_text()) == {"cookies": [{"name": "SID", "value": "x"}]}
    assert path.stat().st_mode & 0o777 == 0o600


def test_save_cookies_warns_instead_of_raising_when_browser_is_gone(tmp_path, capsys):
    closed = browser.PWError("Target page, context or browser has been closed")

    class DeadContext:
        def cookies(self):
            raise closed

    path = tmp_path / "state.json"
    browser._save_cookies(cast("Any", DeadContext()), path)
    assert not path.exists()
    assert "could not save session cookies" in capsys.readouterr().err


class FakeLocator:
    """Minimal locator: visibility comes from a callable, clicks fire a hook."""

    def __init__(self, visible, on_click=None, count=1, text=""):
        self._visible = visible
        self._on_click = on_click
        self._count = count
        self._text = text
        self.filled = None

    def inner_text(self):
        return self._text

    @property
    def first(self):
        return self

    def is_visible(self):
        return self._visible()

    def count(self):
        return self._count

    def click(self, timeout=None):
        if self._on_click:
            self._on_click()

    def fill(self, value):
        self.filled = value


class FakeChallengePage:
    """A Google form that accepts or rejects submitted secrets from a script."""

    field_selector = ""
    next_selector = ""
    rejected_texts = ()

    def __init__(self, verdicts):
        self.verdicts = list(verdicts)
        self.submitted = []
        self.typed = ""
        self.rejected = False
        self.solved = False
        self.keyboard = self

    # -- helpers the code under test drives ---------------------------------
    def locator(self, selector):
        if selector == self.field_selector:
            return FakeLocator(lambda: not self.solved, on_click=None)
        if selector == self.next_selector:
            return FakeLocator(lambda: True, on_click=self._submit)
        return FakeLocator(lambda: False, count=0)

    def get_by_text(self, text, exact=False):
        visible = self.rejected and text in self.rejected_texts
        return FakeLocator(lambda: visible)

    def insert_text(self, char):
        self.typed += char

    def press(self, _key):
        self._submit()

    def wait_for_timeout(self, _ms):
        pass

    # -- the challenge itself ------------------------------------------------
    def _submit(self):
        self.submitted.append(self.typed)
        self.typed = ""
        if self.verdicts.pop(0) == "accept":
            self.solved = True
            self.rejected = False
        else:
            self.rejected = True


class FakeTotpPage(FakeChallengePage):
    field_selector = browser.TOTP_INPUT_SELECTOR
    next_selector = "#totpNext"
    rejected_texts = browser.TOTP_REJECTED


class FakePasswordPage(FakeChallengePage):
    field_selector = "input[type='password']"
    next_selector = "#passwordNext"
    rejected_texts = browser.PASSWORD_REJECTED


class FakeRejectedPage:
    """Google's dead-end error page: no form on it, just the rejection text."""

    def __init__(self, heading="Couldn’t sign you in", body="This browser or app may not be secure. Learn more"):
        self.heading = heading
        self.body = body

    def locator(self, selector):
        if selector == "main":
            return FakeLocator(lambda: True, text=f"{self.heading}\n{self.body}\nTry using a different browser.")
        return FakeLocator(lambda: False, count=0)

    def get_by_text(self, text, exact=False):
        return FakeLocator(lambda: text in self.heading or text in self.body)

    def wait_for_timeout(self, _ms):
        pass


def test_error_page_fails_the_login_instead_of_waiting_it_out():
    page = FakeRejectedPage()

    with pytest.raises(browser.LoginError) as exc:
        browser._wait_visible_or_captured(cast("Any", page), FakeLocator(lambda: False), {}, 30_000)

    # The recognised cause, plus what the page actually said.
    assert "--no-headless" in str(exc.value)
    assert "Couldn’t sign you in" in str(exc.value)
    assert "This browser or app may not be secure" in str(exc.value)


def test_unknown_error_page_still_fails_with_the_page_text():
    page = FakeRejectedPage(body="Something new went wrong")

    with pytest.raises(browser.LoginError, match="Google stopped the sign-in"):
        browser._raise_if_rejected(cast("Any", page))


def test_missing_google_account_page_fails():
    page = FakeRejectedPage(heading="Couldn't find your Google Account", body="Try again")

    with pytest.raises(browser.LoginError, match="Couldn't find your Google Account"):
        browser._raise_if_rejected(cast("Any", page))


def test_totp_steering_bails_out_on_an_error_page():
    with pytest.raises(browser.LoginError, match="Google"):
        _run_totp(FakeRejectedPage(), browser.TotpProvider("", prompt=pytest.fail))


def test_ordinary_page_is_not_treated_as_a_rejection():
    browser._raise_if_rejected(cast("Any", FakeTotpPage(["accept"])))


def _run_totp(page, provider, captured=None):
    """Call the TOTP handler with a stand-in page."""
    return browser._handle_totp(cast("Any", page), provider, captured if captured is not None else {})


def _run_password(page, provider, captured=None):
    """Call the password handler with a stand-in page."""
    return browser._fill_password(cast("Any", page), provider, captured if captured is not None else {})


def test_password_retries_with_a_fresh_prompt_after_a_wrong_password(capsys):
    page = FakePasswordPage(["reject", "accept"])
    provider = browser.PasswordProvider("stale-pw", prompt=lambda: "typed-pw")

    _run_password(page, provider)

    assert page.submitted == ["stale-pw", "typed-pw"]
    assert "rejected the password" in capsys.readouterr().err


def test_password_retries_without_a_limit():
    page = FakePasswordPage(["reject"] * 10 + ["accept"])
    provider = browser.PasswordProvider("stale-pw", prompt=lambda: "typed-pw")

    _run_password(page, provider)

    assert len(page.submitted) == 11


def test_password_submits_once_when_accepted():
    page = FakePasswordPage(["accept"])
    _run_password(page, browser.PasswordProvider("good-pw"))
    assert page.submitted == ["good-pw"]


def test_password_step_is_skipped_when_the_form_never_appears():
    """A reused session lands on the SAML redirect without a password form."""
    page = FakePasswordPage([])
    page.solved = True  # field not visible from the start
    provider = browser.PasswordProvider("", prompt=pytest.fail)

    _run_password(page, provider)

    assert page.submitted == []


def test_password_provider_hands_out_the_configured_password_once():
    provider = browser.PasswordProvider("configured", prompt=lambda: "prompted")
    assert provider.password() == "configured"
    assert provider.password() == "prompted"
    assert provider.password() == "prompted"


def test_password_provider_prompts_when_nothing_is_configured():
    provider = browser.PasswordProvider("", prompt=lambda: "prompted")
    assert provider.password() == "prompted"


def test_password_provider_without_a_prompt_reports_the_rejection():
    provider = browser.PasswordProvider("configured")
    assert provider.password() == "configured"
    with pytest.raises(browser.LoginError, match="was rejected"):
        provider.password()


def test_password_provider_without_password_or_prompt_errors():
    with pytest.raises(browser.LoginError, match="No Google password configured"):
        browser.PasswordProvider("").password()


def test_totp_retries_with_a_fresh_prompt_after_a_wrong_code(capsys):
    page = FakeTotpPage(["reject", "accept"])
    codes = iter(["111111", "222222"])
    provider = browser.TotpProvider("", prompt=lambda: next(codes))

    _run_totp(page, provider)

    assert page.submitted == ["111111", "222222"]
    assert "rejected the TOTP code" in capsys.readouterr().err


def test_totp_clears_the_rejected_code_before_retyping(monkeypatch):
    page = FakeTotpPage(["reject", "accept"])
    fills = []
    real_locator = page.locator

    def spy(selector):
        locator = real_locator(selector)
        if selector == browser.TOTP_INPUT_SELECTOR:
            locator.fill = fills.append
        return locator

    monkeypatch.setattr(page, "locator", spy)
    _run_totp(page, browser.TotpProvider("", prompt=lambda: "123456"))
    assert fills == ["", ""]


def test_totp_retries_without_a_limit():
    # Well past both the old 3-attempt cap and the TOTP_NAV_STEPS budget, which
    # bounds the steering only.
    rejections = browser.TOTP_NAV_STEPS + 10
    page = FakeTotpPage(["reject"] * rejections + ["accept"])
    provider = browser.TotpProvider("", prompt=lambda: "000000")

    _run_totp(page, provider)

    assert len(page.submitted) == rejections + 1


def test_totp_submits_once_when_the_code_is_accepted():
    page = FakeTotpPage(["accept"])
    _run_totp(page, browser.TotpProvider("", prompt=lambda: "123456"))
    assert page.submitted == ["123456"]


def test_totp_stops_when_the_assertion_arrives_mid_challenge():
    page = FakeTotpPage(["reject"])
    captured = {}

    def code():
        captured["saml"] = "ASSERTION"  # the POST lands while we are typing
        return "123456"

    _run_totp(page, browser.TotpProvider("", prompt=code), captured)
    assert len(page.submitted) == 1


def test_prompted_provider_never_waits_for_a_new_code():
    provider = browser.TotpProvider("", prompt=lambda: "123456")
    provider.code()
    assert provider.seconds_until_new_code() == 0


def test_generated_provider_waits_out_the_window_it_already_used():
    provider = browser.TotpProvider(f"otpauth://totp/AWS?secret={SECRET}")
    assert provider.seconds_until_new_code() == 0  # nothing issued yet
    provider.code()
    remaining = provider.seconds_until_new_code()
    assert 0 < remaining <= 30


class FakeContext:
    def __init__(self, storage_state):
        self.storage_state = storage_state
        self.closed = False

    def new_page(self):
        return FakePage()

    def cookies(self):
        return [{"name": "SID", "value": "fresh"}]

    def close(self):
        self.closed = True


class FakePage:
    def __init__(self):
        self.listeners = []

    def on(self, event, handler):
        self.listeners.append((event, handler))

    def remove_listener(self, event, handler):
        self.listeners.remove((event, handler))

    def goto(self, url):
        pass

    def wait_for_timeout(self, _ms):
        pass


class FakeBrowser:
    def __init__(self):
        self.context = None

    def new_context(self, storage_state=None):
        self.context = FakeContext(storage_state)
        return self.context

    def close(self):
        pass


class FakePlaywright:
    def __init__(self):
        self.browser = FakeBrowser()
        self.chromium = self

    def launch(self, *, headless=False):
        self.headless = headless
        return self.browser

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


@pytest.fixture
def fake_playwright(monkeypatch):
    """Run `fetch_saml_response` against a stubbed browser."""
    pw = FakePlaywright()
    monkeypatch.setattr(browser, "sync_playwright", lambda: pw)
    monkeypatch.setattr(browser, "install", lambda _browsers: True)
    monkeypatch.setattr(browser, "_wait_for_capture", lambda _page, _captured: None)
    return pw


def _succeed(monkeypatch):
    monkeypatch.setattr(
        browser,
        "_google_login",
        lambda _page, _cfg, _pw, _totp, captured: captured.setdefault("saml", "ASSERTION"),
    )


def _fail(monkeypatch):
    monkeypatch.setattr(browser, "_google_login", lambda *_a: None)


def _config():
    return ProfileConfig(url="https://accounts.google.com/o/saml2/initsso", email="a@b.com")


def _state_file(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"cookies": [{"name": "SID", "value": "stale"}]}))
    return path


def test_saved_session_is_loaded_into_the_context(fake_playwright, monkeypatch, tmp_path):
    _succeed(monkeypatch)
    path = _state_file(tmp_path)
    browser.fetch_saml_response(
        _config(), browser.PasswordProvider("pw"), browser.TotpProvider(""), storage_state_path=path
    )
    assert fake_playwright.browser.context.storage_state == str(path)


def test_force_starts_from_a_clean_context(fake_playwright, monkeypatch, tmp_path):
    _succeed(monkeypatch)
    path = _state_file(tmp_path)
    browser.fetch_saml_response(
        _config(),
        browser.PasswordProvider("pw"),
        browser.TotpProvider(""),
        storage_state_path=path,
        ignore_saved_session=True,
    )
    assert fake_playwright.browser.context.storage_state is None


def test_force_refreshes_the_saved_session_on_success(fake_playwright, monkeypatch, tmp_path):
    _succeed(monkeypatch)
    path = _state_file(tmp_path)
    assert (
        browser.fetch_saml_response(
            _config(),
            browser.PasswordProvider("pw"),
            browser.TotpProvider(""),
            storage_state_path=path,
            ignore_saved_session=True,
        )
        == "ASSERTION"
    )
    assert json.loads(path.read_text()) == {"cookies": [{"name": "SID", "value": "fresh"}]}


def test_failed_login_leaves_the_saved_session_untouched(fake_playwright, monkeypatch, tmp_path):
    _fail(monkeypatch)
    path = _state_file(tmp_path)
    with pytest.raises(browser.LoginError, match="Did not capture"):
        browser.fetch_saml_response(
            _config(),
            browser.PasswordProvider("pw"),
            browser.TotpProvider(""),
            storage_state_path=path,
            ignore_saved_session=True,
        )
    assert json.loads(path.read_text()) == {"cookies": [{"name": "SID", "value": "stale"}]}


def test_request_listener_is_detached_before_teardown(fake_playwright, monkeypatch, tmp_path):
    _succeed(monkeypatch)
    captured_pages = []
    monkeypatch.setattr(FakeContext, "new_page", lambda _self: captured_pages[0])
    captured_pages.append(FakePage())
    browser.fetch_saml_response(
        _config(), browser.PasswordProvider("pw"), browser.TotpProvider(""), storage_state_path=tmp_path / "s.json"
    )
    assert captured_pages[0].listeners == []
    assert fake_playwright.browser.context.closed


def test_signin_regex_matches_aws_signin_endpoints():
    assert browser.SIGNIN_RE.match("https://signin.aws.amazon.com/saml")
    assert browser.SIGNIN_RE.match("https://ap-northeast-1.signin.aws.amazon.com/saml")
    assert browser.SIGNIN_RE.match("https://signin.amazonaws.cn/saml")
    assert not browser.SIGNIN_RE.match("https://accounts.google.com/saml2/idp")
