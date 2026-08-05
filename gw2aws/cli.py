"""Command-line interface: `gw2aws configure` and `gw2aws login`."""

from __future__ import annotations

import argparse
import getpass
import sys

from gw2aws import aws, config
from gw2aws.browser import LoginError, TotpProvider, fetch_saml_response


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="gw2aws",
        description="SAML login to AWS via Google Workspace (Playwright).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_conf = sub.add_parser("configure", help="Create/update a profile interactively.")
    p_conf.add_argument("-p", "--profile", required=True, help="AWS profile name.")
    p_conf.set_defaults(func=cmd_configure)

    p_login = sub.add_parser("login", help="Log in and write AWS credentials.")
    p_login.add_argument("-p", "--profile", required=True, help="AWS profile name.")
    p_login.add_argument(
        "--headless",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Run the browser headlessly (no visible window). Use --no-headless to show it.",
    )
    p_login.set_defaults(func=cmd_login)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (LoginError, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\naborted", file=sys.stderr)
        return 130


def _prompt(text: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{text}{suffix}: ").strip()
    return value or default


def cmd_configure(args: argparse.Namespace) -> int:
    try:
        existing = config.load(args.profile)
    except FileNotFoundError:
        existing = config.ProfileConfig()

    print(f"Configuring profile '{args.profile}'. Press Enter to keep the current value.\n")

    url = _prompt("Google SAML SSO login URL", existing.url)
    email = _prompt("Google Workspace email", existing.email)

    print("\nPassword and TOTP are optional. If left blank you will be prompted at login.")
    print("If provided, they are stored in plaintext (file mode 0600).")
    password = getpass.getpass("Google password (optional, hidden): ").strip() or existing.password
    totp_url = _prompt("TOTP otpauth:// URL (optional)", existing.totp_url)

    region = _prompt("AWS region for STS", existing.region or "us-east-1")
    role_arn = _prompt("Default role ARN (optional, skips role prompt)", existing.role_arn)
    duration_raw = _prompt("Session duration seconds", str(existing.session_duration or 3600))
    try:
        session_duration = int(duration_raw)
    except ValueError:
        print("Invalid duration; using 3600.")
        session_duration = 3600

    cfg = config.ProfileConfig(
        url=url,
        email=email,
        password=password,
        totp_url=totp_url,
        region=region,
        role_arn=role_arn,
        session_duration=session_duration,
    )
    path = config.save(args.profile, cfg)
    print(f"\nSaved: {path}")
    return 0


def cmd_login(args: argparse.Namespace) -> int:
    cfg = config.load(args.profile)
    if not cfg.url or not cfg.email:
        raise ValueError(f"Profile '{args.profile}' is missing url/email. Run `gw2aws configure` first.")

    password = cfg.password
    if not password:
        password = getpass.getpass(f"Google password for {cfg.email}: ")

    totp = TotpProvider(
        totp_url=cfg.totp_url,
        prompt=lambda: input("Google Authenticator code: ").strip(),
    )

    print("Opening browser for Google Workspace login ...", file=sys.stderr)
    print(
        "(The first run may take a while to download the headless browser and driver.)",
        file=sys.stderr,
    )
    saml_assertion = fetch_saml_response(
        cfg,
        password=password,
        totp_provider=totp,
        headless=args.headless,
        storage_state_path=config.storage_state_path(args.profile),
    )

    roles = aws.extract_roles(saml_assertion)
    if not roles:
        raise LoginError("No AWS roles found in the SAML assertion.")

    role = _resolve_role(roles, cfg.role_arn)
    print(f"Assuming role: {role.role_arn}", file=sys.stderr)

    duration = aws.extract_session_duration(saml_assertion, cfg.session_duration)
    creds = aws.assume_role(role, saml_assertion, cfg.region, duration)
    path = aws.save_credentials(args.profile, creds)

    print(f"Logged in as: {creds.principal_arn}")
    print(f"Credentials expire at: {creds.expiration.astimezone().isoformat()}")
    print(f"Written to: {path} (profile '{args.profile}')")
    return 0


def _resolve_role(roles: list[aws.AWSRole], configured_arn: str) -> aws.AWSRole:
    if configured_arn:
        for role in roles:
            if role.role_arn == configured_arn:
                return role
        raise LoginError(f"Configured role_arn not present in assertion: {configured_arn}")
    if len(roles) == 1:
        return roles[0]

    print("\nAvailable roles:")
    for i, role in enumerate(roles):
        print(f"  [{i}] {role.name}")
    while True:
        choice = input(f"Select role [0-{len(roles) - 1}]: ").strip()
        if choice.isdigit() and 0 <= int(choice) < len(roles):
            return roles[int(choice)]
        print("Invalid selection.")


if __name__ == "__main__":
    raise SystemExit(main())
