# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Password helpers."""

import secrets
import string


def generate_password(length) -> str:
    """Generate a password with the given policy.

    Args:
        length: The length of the password to be generated. Defaults to 12.

    Return:
        The generated password.

    Raises:
        ValueError: If the password length is too short.
    """
    if length < 8:
        raise ValueError("Password length is too short.")

    hard_to_escape = set("'" + '"')
    characters = "".join(
        set(string.ascii_letters + string.digits + string.punctuation) - set(hard_to_escape)
    )
    while True:
        password = "".join(secrets.choice(characters) for i in range(length))
        # At least 1 upper letter, 1 lower letter and 1 digit
        if (
            sum(c.islower() for c in password) >= 1
            and any(c.isupper() for c in password) >= 1
            and sum(c.isdigit() for c in password) >= 1
        ):
            break

    return password
