# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Password helpers."""

import secrets
import string


def generate_password() -> str:
    """Generate a password with the given policy.

    Return:
        The generated password.
    """
    characters = string.ascii_letters + string.digits
    while True:
        password = "".join(secrets.choice(characters) for i in range(10))
        # At least 1 upper letter, 1 lower letter and 1 digit
        if (
            sum(c.islower() for c in password) >= 1
            and any(c.isupper() for c in password) >= 1
            and sum(c.isdigit() for c in password) >= 1
        ):
            break

    return password
