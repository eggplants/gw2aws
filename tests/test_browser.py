"""Tests for gw2aws.browser (pure logic; no real browser)."""

from __future__ import annotations

import urllib.parse

import pyotp
import pytest

from gw2aws import browser

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


def test_signin_regex_matches_aws_signin_endpoints():
    assert browser.SIGNIN_RE.match("https://signin.aws.amazon.com/saml")
    assert browser.SIGNIN_RE.match("https://ap-northeast-1.signin.aws.amazon.com/saml")
    assert browser.SIGNIN_RE.match("https://signin.amazonaws.cn/saml")
    assert not browser.SIGNIN_RE.match("https://accounts.google.com/saml2/idp")
