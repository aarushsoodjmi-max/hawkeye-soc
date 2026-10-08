"""Generate PBKDF2-SHA256 password hashes for AUTH_USERS_JSON."""
from __future__ import annotations

import argparse
import hashlib
import secrets


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("password", nargs="?", help="Password to hash; prompted securely when omitted")
    parser.add_argument("--iterations", type=int, default=600_000)
    args = parser.parse_args()

    if args.password is None:
        import getpass
        password = getpass.getpass("Password: ")
    else:
        password = args.password

    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), args.iterations
    ).hex()
    print(f"pbkdf2_sha256${args.iterations}${salt}${digest}")


if __name__ == "__main__":
    main()
