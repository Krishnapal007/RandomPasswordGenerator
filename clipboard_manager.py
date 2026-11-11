


class ClipboardError(Exception):
    """Raised when the text could not be copied."""


class PyperclipBackend:
    """Backend that uses the pyperclip library (imported only when needed)."""

    def __init__(self):
        try:
            import pyperclip
        except ImportError:
            pyperclip = None
        self._module = pyperclip

    def copy(self, text):
        if self._module is None:
            raise RuntimeError("pyperclip is not installed (run: pip install pyperclip)")
        self._module.copy(text)

    def paste(self):
        if self._module is None:
            raise RuntimeError("pyperclip is not installed")
        return self._module.paste()


class ClipboardManager:
    def __init__(self, backends=None):
        self.backends = list(backends) if backends is not None else [PyperclipBackend()]

    def copy(self, text):
        """Copy `text`. Raises ClipboardError if every backend fails."""
        if not isinstance(text, str) or not text:
            raise ClipboardError("There is no password to copy yet. Generate one first.")
        problems = []
        for backend in self.backends:
            try:
                backend.copy(text)
            except Exception as exc:  
                problems.append(str(exc) or exc.__class__.__name__)
                continue
            try:                      
                if backend.paste() != text:
                    problems.append("the clipboard did not keep the text")
                    continue
            except Exception:         
                pass
            return True
        detail = "; ".join(problems) if problems else "no clipboard backend is available"
        raise ClipboardError(f"Could not access the clipboard ({detail}).")

    def clear_if_matches(self, text):
        """
        Empty the clipboard, but only if it still contains `text`
        (so we never erase something else the user copied later). Returns True if cleared.
        """
        for backend in self.backends:
            try:
                if backend.paste() == text:
                    backend.copy("")
                    return True
                return False
            except Exception:  
                continue
        return False
