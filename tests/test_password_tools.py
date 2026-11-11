
import builtins
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import password_generator as pg
from clipboard_manager import ClipboardError, ClipboardManager, PyperclipBackend
from history_manager import HistoryManager
from password_generator import PasswordError, PasswordOptions, generate_password
from password_strength import evaluate_password


def opts(**kwargs):
    return PasswordOptions(**kwargs)


class LengthTests(unittest.TestCase):
    def test_8_16_and_128_characters(self):          
        for length in (8, 16, 128):
            password = generate_password(opts(length=length))
            self.assertEqual(len(password), length)

    def test_default_options(self):
        self.assertEqual(len(generate_password()), 16)


class CharacterTypeTests(unittest.TestCase):
    def test_every_selected_type_is_always_present(self):   
        for _ in range(3000):
            p = generate_password(opts(length=8))
            self.assertTrue(re.search("[A-Z]", p) and re.search("[a-z]", p)
                            and re.search("[0-9]", p) and any(c in pg.SYMBOLS for c in p), p)

    def test_each_pair_of_types(self):                     
        sets = {"upper": pg.UPPERCASE, "lower": pg.LOWERCASE, "digit": pg.DIGITS, "symbol": pg.SYMBOLS}
        flags = {"upper": "use_uppercase", "lower": "use_lowercase", "digit": "use_digits", "symbol": "use_symbols"}
        names = list(sets)
        for i, first in enumerate(names):
            for second in names[i + 1:]:
                kwargs = {flag: False for flag in flags.values()}
                kwargs[flags[first]] = kwargs[flags[second]] = True
                for _ in range(200):
                    p = generate_password(opts(length=8, **kwargs))
                    self.assertTrue(any(c in sets[first] for c in p), (first, second, p))
                    self.assertTrue(any(c in sets[second] for c in p), (first, second, p))
                    allowed = sets[first] + sets[second]
                    self.assertTrue(all(c in allowed for c in p), (first, second, p))

    def test_three_types_exclude_the_fourth(self):
        for _ in range(300):
            p = generate_password(opts(use_symbols=False))
            self.assertTrue(all(c.isalnum() for c in p))

    def test_minimum_two_types(self):                        
        single = [dict(use_uppercase=True, use_lowercase=False, use_digits=False, use_symbols=False),
                  dict(use_uppercase=False, use_lowercase=True, use_digits=False, use_symbols=False),
                  dict(use_uppercase=False, use_lowercase=False, use_digits=True, use_symbols=False),
                  dict(use_uppercase=False, use_lowercase=False, use_digits=False, use_symbols=True),
                  dict(use_uppercase=False, use_lowercase=False, use_digits=False, use_symbols=False)]
        for kwargs in single:
            with self.assertRaisesRegex(PasswordError, "at least 2"):
                generate_password(opts(**kwargs))


class InvalidInputTests(unittest.TestCase):
    def test_invalid_length(self):                           
        for bad in (7, 129, 0, -5, 1000):
            with self.assertRaisesRegex(PasswordError, "between 8 and 128"):
                generate_password(opts(length=bad))
        for bad in ("16", 16.5, None, True, [16]):
            with self.assertRaisesRegex(PasswordError, "whole number"):
                generate_password(opts(length=bad))

    def test_invalid_flags(self):
        with self.assertRaises(PasswordError):
            generate_password(opts(use_symbols="yes"))

    def test_boundaries_are_accepted(self):
        self.assertEqual(len(generate_password(opts(length=pg.MIN_LENGTH))), 8)
        self.assertEqual(len(generate_password(opts(length=pg.MAX_LENGTH))), 128)


class AmbiguousTests(unittest.TestCase):
    def test_ambiguous_characters_excluded(self):            
        for _ in range(1500):
            p = generate_password(opts(length=24, exclude_ambiguous=True))
            self.assertFalse(set(p) & set("0O1l"), p)
        for pool in pg.build_pools(opts(exclude_ambiguous=True)):
            self.assertFalse(set(pool) & set(pg.AMBIGUOUS))
            self.assertTrue(pool)

    def test_ambiguous_characters_appear_when_not_excluded(self):
        seen = set("".join(generate_password(opts(length=64)) for _ in range(50)))
        self.assertTrue(set("0O1l") <= seen)


class SecurityTests(unittest.TestCase):
    def test_no_random_module(self):
        source = (ROOT / "password_generator.py").read_text()
        self.assertNotRegex(source, r"^\s*(import random|from random)", )
        self.assertIn("import secrets", source)

    def test_secrets_drives_selection_and_shuffle(self):
        with mock.patch.object(pg.secrets, "randbelow", wraps=pg.secrets.randbelow) as randbelow, \
                mock.patch.object(pg.secrets, "choice", wraps=pg.secrets.choice) as choice:
            generate_password(opts(length=20))
        self.assertEqual(choice.call_count, 20)
        self.assertEqual(randbelow.call_count, 19)  

    def test_passwords_differ_and_order_is_shuffled(self):
        passwords = {generate_password(opts(length=16)) for _ in range(500)}
        self.assertEqual(len(passwords), 500)
        first_char_types = {("upper" if p[0].isupper() else "lower" if p[0].islower() else
                             "digit" if p[0].isdigit() else "symbol") for p in passwords}
        self.assertEqual(len(first_char_types), 4)  

    def test_secure_shuffle_keeps_all_items(self):
        items = list(range(50))
        pg.secure_shuffle(items)
        self.assertEqual(sorted(items), list(range(50)))


class FakeBackend:
    def __init__(self, fail=False, broken_paste=False, lose_text=False):
        self.value, self.fail, self.broken_paste, self.lose_text = "", fail, broken_paste, lose_text

    def copy(self, text):
        if self.fail:
            raise OSError("clipboard unavailable")
        self.value = "" if self.lose_text else text

    def paste(self):
        if self.broken_paste:
            raise OSError("cannot read")
        return self.value


class ClipboardTests(unittest.TestCase):
    def test_copy_success(self):                             
        backend = FakeBackend()
        self.assertTrue(ClipboardManager([backend]).copy("S3cret!pass"))
        self.assertEqual(backend.value, "S3cret!pass")

    def test_copy_empty_is_an_error(self):
        for bad in ("", None, 123):
            with self.assertRaisesRegex(ClipboardError, "no password"):
                ClipboardManager([FakeBackend()]).copy(bad)

    def test_failure_is_reported_not_raised_as_os_error(self):
        with self.assertRaisesRegex(ClipboardError, "Could not access the clipboard"):
            ClipboardManager([FakeBackend(fail=True)]).copy("abc12345")

    def test_fallback_backend_is_used(self):
        good = FakeBackend()
        self.assertTrue(ClipboardManager([FakeBackend(fail=True), good]).copy("abc12345"))
        self.assertEqual(good.value, "abc12345")

    def test_copy_that_does_not_stick_is_detected(self):
        with self.assertRaises(ClipboardError):
            ClipboardManager([FakeBackend(lose_text=True)]).copy("abc12345")

    def test_unreadable_clipboard_still_counts_as_copied(self):
        self.assertTrue(ClipboardManager([FakeBackend(broken_paste=True)]).copy("abc12345"))

    def test_pyperclip_missing(self):
        with mock.patch.dict(sys.modules, {"pyperclip": None}):
            manager = ClipboardManager([PyperclipBackend()])
            with self.assertRaisesRegex(ClipboardError, "pyperclip is not installed"):
                manager.copy("abc12345")

    def test_pyperclip_used_when_available(self):
        fake = mock.Mock()
        stored = {}
        fake.copy.side_effect = lambda t: stored.update(v=t)
        fake.paste.side_effect = lambda: stored["v"]
        with mock.patch.dict(sys.modules, {"pyperclip": fake}):
            self.assertTrue(ClipboardManager().copy("abc12345"))
        fake.copy.assert_called_with("abc12345")

    def test_clear_only_if_unchanged(self):
        backend = FakeBackend()
        manager = ClipboardManager([backend])
        manager.copy("abc12345")
        self.assertTrue(manager.clear_if_matches("abc12345"))
        self.assertEqual(backend.value, "")
        backend.value = "something else the user copied"
        self.assertFalse(manager.clear_if_matches("abc12345"))
        self.assertEqual(backend.value, "something else the user copied")


class StrengthTests(unittest.TestCase):
    def test_labels(self):                                   
        self.assertEqual(evaluate_password("").label, "Weak")
        self.assertEqual(evaluate_password("abcdefgh").label, "Weak")       
        self.assertEqual(evaluate_password("Ab3$Ef6&").label, "Medium")     
        self.assertEqual(evaluate_password("Ab3$Ef6&Hk9#").label, "Strong") 
        self.assertEqual(evaluate_password("a" * 40).label, "Strong")        
        self.assertEqual(evaluate_password(generate_password(opts(length=16))).label, "Strong")

    def test_more_length_or_diversity_never_lowers_score(self):
        scores = [evaluate_password(generate_password(opts(length=n))).score for n in (8, 12, 16, 32)]
        self.assertEqual(scores, sorted(scores))
        self.assertLess(evaluate_password("abcdefgh").score, evaluate_password("abcDEF12").score)

    def test_score_range_and_details(self):
        result = evaluate_password("Ab3$Ef6&Hk9#" * 20)
        self.assertEqual(result.score, 1.0)
        self.assertEqual((result.character_types, result.length), (4, 240))
        self.assertEqual(evaluate_password("password").color, "#ef4444")
        with self.assertRaises(TypeError):
            evaluate_password(None)


class HistoryTests(unittest.TestCase):
    def test_only_last_five_kept_newest_first(self):         
        history = HistoryManager()
        for i in range(1, 9):
            history.add(f"password{i}")
        self.assertEqual(len(history), 5)
        self.assertEqual(history.get_all(), [f"password{i}" for i in (8, 7, 6, 5, 4)])
        self.assertEqual(history.get(0), "password8")

    def test_clear(self):
        history = HistoryManager()
        history.add("abc12345")
        history.clear()
        self.assertEqual((len(history), history.get_all()), (0, []))
        with self.assertRaises(IndexError):
            history.get(0)

    def test_rejects_bad_values(self):
        for bad in ("", None, 5):
            with self.assertRaises(ValueError):
                HistoryManager().add(bad)


class NotStoredTests(unittest.TestCase):
    def test_nothing_is_written_to_disk(self):                
        real_open = builtins.open
        written = []

        def spy(file, mode="r", *args, **kwargs):
            if any(flag in mode for flag in "wax+"):
                written.append(file)
            return real_open(file, mode, *args, **kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                with mock.patch("builtins.open", spy):
                    history = HistoryManager()
                    clipboard = ClipboardManager([FakeBackend()])
                    for _ in range(20):
                        password = generate_password()
                        evaluate_password(password)
                        history.add(password)
                        clipboard.copy(password)
                    history.clear()
                self.assertEqual(os.listdir(tmp), [])
            finally:
                os.chdir(previous)
        self.assertEqual(written, [])

    def test_source_code_has_no_file_or_database_writes(self):
        for name in ("password_generator.py", "password_strength.py", "clipboard_manager.py",
                     "history_manager.py", "main.py"):
            path = ROOT / name
            if not path.exists():
                continue
            code = path.read_text()
            for forbidden in ("open(", "sqlite3", "pickle", "shelve", "json.dump", "write_text", "logging"):
                self.assertNotIn(forbidden, code, f"{name} contains {forbidden}")


if __name__ == "__main__":
    unittest.main()
