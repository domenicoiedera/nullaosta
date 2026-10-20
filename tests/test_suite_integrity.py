"""Suite integrity: the suite must not be able to disappear quietly.

Every other test here defends the library. This one defends the tests.

Why it exists: CI runs exactly one command, ``python -m unittest discover -s
tests -t .``, and that command exits 0 when a test *module* is emptied or
deleted, because it simply collects fewer tests and reports OK. Measured on this
repo before this guard existed:

  tests/test_engine.py gutted to 0 bytes        -> exit 0, "OK"
  tests/test_tamper.py deleted outright         -> exit 0, "OK" (32 tests ran)

So a green run did not prove the tests were still present. An empty or missing
``tests/`` *directory* is caught by discovery itself (ImportError, exit 1), but a
single vanished module was not.

Cost of the guard: MINIMUM_TESTS must be raised on purpose when tests are added.
That is the point. Lowering it to turn a red run green re-opens the hole.
"""

import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

# The modules that carry the suite's weight. A missing or empty file here means
# tests were removed, not refactored.
REQUIRED_MODULES = (
    "test_engine.py",
    "test_tamper.py",
    "test_cli_e2e.py",
)

# Measured 2026-10-20 on the v0.1.0 tree: 49 tests, before this file was added.
# A floor rather than an equality, so adding tests is free.
MINIMUM_TESTS = 49


def _defines_tests(module_name):
    path = os.path.join(HERE, module_name)
    with open(path, "rb") as fh:
        return fh.read().decode("utf-8", "replace").count("def test_")


class TestSuiteIntegrity(unittest.TestCase):
    def test_required_modules_present_and_not_empty(self):
        for name in REQUIRED_MODULES:
            with self.subTest(module=name):
                path = os.path.join(HERE, name)
                self.assertTrue(os.path.isfile(path), f"{name} is missing")
                self.assertGreater(os.path.getsize(path), 0, f"{name} is empty")
                self.assertGreater(
                    _defines_tests(name), 0, f"{name} defines no tests"
                )

    def test_collected_total_meets_floor(self):
        loader = unittest.TestLoader()
        try:
            suite = loader.discover(HERE, top_level_dir=os.path.dirname(HERE))
        except Exception as exc:  # discovery must never fail silently
            self.fail(f"test discovery failed: {exc!r}")
        total = suite.countTestCases()
        self.assertGreaterEqual(
            total,
            MINIMUM_TESTS,
            f"only {total} tests were collected but the floor is {MINIMUM_TESTS}: "
            "test modules have been removed, emptied or gutted",
        )
