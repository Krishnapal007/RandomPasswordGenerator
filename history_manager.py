"""
history_manager.py - Remembers the last few passwords of the CURRENT session only.

The history lives in memory (a deque). It is never written to a file or database,
and it disappears when the program closes.
"""

from collections import deque

MAX_HISTORY = 5


class HistoryManager:
    def __init__(self, max_items=MAX_HISTORY):
        if max_items < 1:
            raise ValueError("max_items must be at least 1")
        self._items = deque(maxlen=max_items)  

    def add(self, password):
        if not isinstance(password, str) or not password:
            raise ValueError("Only non-empty passwords can be stored in the history.")
        self._items.appendleft(password)

    def get_all(self):
        """Newest first."""
        return list(self._items)

    def get(self, index):
        """Return the password at `index` (0 = newest) or raise IndexError."""
        return self._items[index]

    def clear(self):
        self._items.clear()

    def __len__(self):
        return len(self._items)
