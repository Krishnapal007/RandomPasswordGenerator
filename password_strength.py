"""
password_strength.py - Estimate password strength from length and character diversity.

Estimated entropy (bits) = length * log2(size of the character pool the password uses).
This is an estimate for randomly generated passwords, not a guarantee.

    Weak   : below 50 bits
    Medium : 50 - 74 bits
    Strong : 75 bits or more
"""

import math
import string
from dataclasses import dataclass

WEAK_LIMIT = 50.0
STRONG_LIMIT = 75.0
BAR_FULL_AT = 100.0  

COLORS = {"Weak": "#ef4444", "Medium": "#f59e0b", "Strong": "#22c55e"}


@dataclass(frozen=True)
class StrengthResult:
    label: str          
    score: float        
    entropy_bits: float
    character_types: int
    length: int

    @property
    def color(self):
        return COLORS[self.label]


def _pool_size(password):
    """Size of the character pool implied by the kinds of characters in the password."""
    size, types = 0, 0
    if any(c in string.ascii_lowercase for c in password):
        size, types = size + 26, types + 1
    if any(c in string.ascii_uppercase for c in password):
        size, types = size + 26, types + 1
    if any(c in string.digits for c in password):
        size, types = size + 10, types + 1
    if any(c in string.punctuation for c in password):
        size, types = size + 32, types + 1
    if any(not c.isascii() or c == " " for c in password):  
        size, types = size + 20, types + 1
    return size, types


def evaluate_password(password):
    """Return a StrengthResult for `password`."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if not password:
        return StrengthResult("Weak", 0.0, 0.0, 0, 0)
    size, types = _pool_size(password)
    entropy = len(password) * math.log2(size)
    if entropy < WEAK_LIMIT:
        label = "Weak"
    elif entropy < STRONG_LIMIT:
        label = "Medium"
    else:
        label = "Strong"
    return StrengthResult(label, min(1.0, entropy / BAR_FULL_AT), round(entropy, 1), types, len(password))
