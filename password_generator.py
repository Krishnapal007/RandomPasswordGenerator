"""
password_generator.py - Cryptographically secure password generation.

Security rules followed here
----------------------------
* Only the `secrets` module is used for randomness (never `random`).
* At least one character from EVERY selected character type is guaranteed.
* The final character order is shuffled with a Fisher-Yates shuffle driven by
  `secrets.randbelow`, so the guaranteed characters are not in predictable places.
* Nothing is written to disk. Passwords only exist in memory.
"""

import secrets
import string
from dataclasses import dataclass

MIN_LENGTH = 8
MAX_LENGTH = 128
DEFAULT_LENGTH = 16
MIN_CHARACTER_TYPES = 2

UPPERCASE = string.ascii_uppercase
LOWERCASE = string.ascii_lowercase
DIGITS = string.digits

SYMBOLS = "".join(c for c in string.punctuation if c not in "\"'`\\|")
AMBIGUOUS = "0O1l"  


class PasswordError(ValueError):
    """Raised when the requested password options are invalid (message is user friendly)."""


@dataclass(frozen=True)
class PasswordOptions:
    """Everything the user can choose."""
    length: int = DEFAULT_LENGTH
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = False

    def selected_types(self):
        """Names of the selected character types."""
        flags = (("uppercase", self.use_uppercase), ("lowercase", self.use_lowercase),
                 ("numbers", self.use_digits), ("symbols", self.use_symbols))
        return [name for name, enabled in flags if enabled]


def validate_options(options):
    """Raise PasswordError with a helpful message if the options are not acceptable."""
    length = options.length
    if isinstance(length, bool) or not isinstance(length, int):
        raise PasswordError("Password length must be a whole number.")
    if not MIN_LENGTH <= length <= MAX_LENGTH:
        raise PasswordError(f"Password length must be between {MIN_LENGTH} and {MAX_LENGTH} characters.")
    for flag in (options.use_uppercase, options.use_lowercase, options.use_digits,
                 options.use_symbols, options.exclude_ambiguous):
        if not isinstance(flag, bool):
            raise PasswordError("Character options must be True or False.")
    if len(options.selected_types()) < MIN_CHARACTER_TYPES:
        raise PasswordError(f"Select at least {MIN_CHARACTER_TYPES} character types "
                            "(uppercase, lowercase, numbers, symbols).")


def build_pools(options):
    """Return one character pool (string) per selected type, minus ambiguous characters if requested."""
    selected = ((options.use_uppercase, UPPERCASE), (options.use_lowercase, LOWERCASE),
                (options.use_digits, DIGITS), (options.use_symbols, SYMBOLS))
    pools = []
    for enabled, characters in selected:
        if enabled:
            if options.exclude_ambiguous:
                characters = "".join(c for c in characters if c not in AMBIGUOUS)
            pools.append(characters)
    return pools


def secure_shuffle(items):
    """In-place Fisher-Yates shuffle using secrets.randbelow (cryptographically secure)."""
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]


def generate_password(options=None):
    """Generate one password that satisfies `options` and return it as a string."""
    options = options or PasswordOptions()
    validate_options(options)
    pools = build_pools(options)
    combined = "".join(dict.fromkeys("".join(pools)))  # all allowed characters, no duplicates

    characters = [secrets.choice(pool) for pool in pools]          
    characters += [secrets.choice(combined) for _ in range(options.length - len(characters))]
    secure_shuffle(characters)
    return "".join(characters)
