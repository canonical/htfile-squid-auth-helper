# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Test the password helpers."""

import pytest

from charm import USER_PASSWORD_LENGTH
from password import generate_password


def test_password_ok():
    """
    act: Call the function with good parameters.
    assert: A value is returned.
    """
    assert generate_password(12)


def test_password_policy():
    """
    act: Call the function with default parameters.
    assert: The generated password matches a mixed characters policy.
    """
    password = generate_password(12)
    contains_digit = False
    contains_upper = False
    contains_lower = False
    contains_special = False
    for c in password:
        if c.isdigit():
            contains_digit = True
        elif c.islower():
            contains_lower = True
        elif c.isupper():
            contains_upper = True
        else:
            contains_special = True

    assert contains_digit
    assert contains_upper
    assert contains_lower
    assert contains_special


def test_password_fixed_length():
    """
    act: Call the function with a specific length.
    assert: The returned string matches the expected length.
    """
    assert len(generate_password(USER_PASSWORD_LENGTH)) == USER_PASSWORD_LENGTH


def test_password_bad_length():
    """
    act: Call the function with a length which is too small.
    assert: The default parameter doesn't raise any errors.
    """
    with pytest.raises(ValueError):
        generate_password(2)
