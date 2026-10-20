"""Tests for tools/release_homebrew.py - the step that keeps the tap honest.

What is being defended: a release must never leave the tap pointing at an older
asset, and the tool must never write a sha256 it did not compute from the bytes
that were actually served. The tests here cover the parsing and rewriting the
tool does on its own; the network paths are exercised by the real release run,
not by CI.
"""

import importlib.util
import io
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _load_tool():
    path = os.path.join(ROOT, "tools", "release_homebrew.py")
    spec = importlib.util.spec_from_file_location("release_homebrew_under_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rh: Any = _load_tool()

NEW_URL = "https://github.com/domenicoiedera/nullaosta/releases/download/v0.2.0/nullaosta-0.2.0.tar.gz"
NEW_SHA = "b" * 64

FORMULA = """class Nullaosta < Formula
  include Language::Python::Virtualenv

  desc "Fail-closed approval gate with verifiable receipts for AI agents"
  homepage "https://github.com/domenicoiedera/nullaosta"
  url "https://github.com/domenicoiedera/nullaosta/releases/download/v0.1.0/nullaosta-0.1.0.tar.gz"
  sha256 "%s"
  license "MIT"

  depends_on "python@3.14"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/nullaosta --version")
  end
end
""" % ("a" * 64)


def _quiet(func, *args, **kwargs):
    """Run something that prints, and return (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = func(*args, **kwargs)
    return code, out.getvalue(), err.getvalue()


class TestProjectVersion(unittest.TestCase):
    def test_reads_the_project_table(self):
        text = (
            "[build-system]\n"
            'requires = ["setuptools>=61"]\n\n'
            "[project]\n"
            'name = "nullaosta"\n'
            'version = "1.2.3"\n\n'
            "[project.scripts]\n"
            'nullaosta = "nullaosta.cli:main"\n'
        )
        self.assertEqual(rh.project_version(text), "1.2.3")

    def test_ignores_version_keys_in_other_tables(self):
        text = (
            "[tool.elsewhere]\n"
            'version = "9.9.9"\n\n'
            "[project]\n"
            'version = "1.2.3"\n\n'
            "[tool.more]\n"
            'version = "8.8.8"\n'
        )
        self.assertEqual(rh.project_version(text), "1.2.3")

    def test_missing_version_raises(self):
        with self.assertRaises(ValueError):
            rh.project_version('[project]\nname = "x"\n')

    def test_the_real_pyproject_is_the_version_the_cli_reports(self):
        with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as handle:
            version = rh.project_version(handle.read())
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")


class TestSdistUrl(unittest.TestCase):
    def test_the_url_is_the_release_asset_for_that_tag(self):
        url = rh.sdist_url("0.2.0")
        self.assertTrue(
            url.startswith(
                "https://github.com/domenicoiedera/nullaosta/releases/download/v0.2.0/"
            ),
            url,
        )
        self.assertTrue(url.endswith("/nullaosta-0.2.0.tar.gz"), url)


class TestFormulaParsing(unittest.TestCase):
    def test_reads_both_pinned_values(self):
        url, sha = rh.formula_state(FORMULA)
        self.assertIn("v0.1.0", url)
        self.assertEqual(sha, "a" * 64)

    def test_a_formula_without_a_sha_raises_rather_than_guessing(self):
        with self.assertRaises(ValueError):
            rh.formula_state(FORMULA.replace('  sha256 "' + "a" * 64 + '"\n', ""))


class TestRewrite(unittest.TestCase):
    def test_only_the_two_pinned_lines_change(self):
        after = rh.rewrite_formula(FORMULA, NEW_URL, NEW_SHA)
        before_lines, after_lines = FORMULA.splitlines(), after.splitlines()
        self.assertEqual(len(before_lines), len(after_lines))
        changed = [(b, a) for b, a in zip(before_lines, after_lines) if b != a]
        self.assertEqual(len(changed), 2, changed)
        self.assertIn(f'url "{NEW_URL}"', changed[0][1])
        self.assertIn(f'sha256 "{NEW_SHA}"', changed[1][1])

    def test_indentation_is_preserved(self):
        after = rh.rewrite_formula(FORMULA, NEW_URL, NEW_SHA)
        for line in after.splitlines():
            if NEW_URL in line or NEW_SHA in line:
                self.assertTrue(line.startswith("  "), line)

    def test_rewriting_twice_is_idempotent(self):
        once = rh.rewrite_formula(FORMULA, NEW_URL, NEW_SHA)
        twice = rh.rewrite_formula(once, NEW_URL, NEW_SHA)
        self.assertEqual(once, twice)

    def test_is_current(self):
        self.assertTrue(rh.is_current(FORMULA, rh.formula_state(FORMULA)[0], "a" * 64))
        self.assertFalse(rh.is_current(FORMULA, NEW_URL, NEW_SHA))


class TestRefusals(unittest.TestCase):
    def test_push_without_a_tap_dir_is_refused(self):
        code, _, err = _quiet(rh.main, ["--push"])
        self.assertEqual(code, 2)
        self.assertIn("--push needs --tap-dir", err)

    def test_check_and_push_together_is_refused(self):
        code, _, err = _quiet(rh.main, ["--check", "--push", "--tap-dir", "/tmp"])
        self.assertEqual(code, 2)
        self.assertIn("--check does not write", err)

    def test_a_tap_dir_inside_the_source_repo_is_refused(self):
        inside = os.path.join(ROOT, "tap-that-should-not-be-here")
        code, _, err = _quiet(rh.main, ["--check", "--tap-dir", inside])
        self.assertEqual(code, 2)
        self.assertIn("inside the source repo", err)

    def test_a_tap_dir_without_a_formula_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err = _quiet(rh.main, ["--check", "--tap-dir", tmp])
        self.assertEqual(code, 2)
        self.assertIn("no formula at", err)


class TestCheckMode(unittest.TestCase):
    def test_a_stale_tap_is_reported_without_downloading(self):
        """The url differs, so the answer is known before any network call."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, rh.FORMULA_PATH)
            os.makedirs(os.path.dirname(path))
            stale = FORMULA.replace("/v0.1.0/", "/v0.0.9/")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(stale)
            code, _, err = _quiet(rh.main, ["--check", "--tap-dir", tmp])
        self.assertEqual(code, 1, err)
        self.assertIn("STALE", err)


class TestWritePath(unittest.TestCase):
    """The write path, with the download replaced by a fixed digest.

    These exist because the verifier pointed out that nothing reached main()'s
    write path: the disk re-read guard could be deleted and the suite stayed
    green. A guard with no test is a guard that will be removed by accident.
    """

    def _tap_with_formula(self, tmp):
        path = os.path.join(tmp, rh.FORMULA_PATH)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(FORMULA)
        return path

    def _expected_url(self):
        with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as handle:
            return rh.sdist_url(rh.project_version(handle.read()))

    def test_writes_the_formula_then_reports_current(self):
        original = rh.sha256_of_url
        rh.sha256_of_url = lambda url, timeout=120: NEW_SHA
        try:
            with tempfile.TemporaryDirectory() as tmp:
                path = self._tap_with_formula(tmp)
                code, out, err = _quiet(rh.main, ["--tap-dir", tmp])
                self.assertEqual(code, 0, err)
                self.assertIn("WROTE", out)
                with open(path, encoding="utf-8") as handle:
                    self.assertEqual(
                        rh.formula_state(handle.read()), (self._expected_url(), NEW_SHA)
                    )
                code, out, _ = _quiet(rh.main, ["--tap-dir", tmp])
                self.assertEqual(code, 0)
                self.assertIn("CURRENT", out)
        finally:
            rh.sha256_of_url = original

    def test_a_write_that_does_not_land_is_caught_by_the_re_read(self):
        original_sha, original_rewrite = rh.sha256_of_url, rh.rewrite_formula
        rh.sha256_of_url = lambda url, timeout=120: NEW_SHA
        rh.rewrite_formula = lambda text, url, sha: text  # a write that changes nothing
        try:
            with tempfile.TemporaryDirectory() as tmp:
                self._tap_with_formula(tmp)
                code, _, err = _quiet(rh.main, ["--tap-dir", tmp])
        finally:
            rh.sha256_of_url, rh.rewrite_formula = original_sha, original_rewrite
        self.assertEqual(code, 1, "a silent no-op write must never report success")
        self.assertIn("FAILED", err)


class TestPushCommitScope(unittest.TestCase):
    """--push must not sweep up anything already staged in the tap's index."""

    def test_a_stray_staged_file_is_not_committed(self):
        original = rh.sha256_of_url
        with tempfile.TemporaryDirectory() as tmp:
            origin = os.path.join(tmp, "origin.git")
            tap = os.path.join(tmp, "tap")
            subprocess.run(["git", "init", "--bare", "-q", origin], check=True, capture_output=True)
            subprocess.run(["git", "clone", "-q", origin, tap], check=True, capture_output=True)
            subprocess.run(["git", "-C", tap, "config", "user.email", "test@example.com"], check=True)
            subprocess.run(["git", "-C", tap, "config", "user.name", "test"], check=True)
            os.makedirs(os.path.join(tap, "Formula"))
            with open(os.path.join(tap, rh.FORMULA_PATH), "w", encoding="utf-8") as handle:
                handle.write(FORMULA)
            with open(os.path.join(tap, "UNRELATED.md"), "w", encoding="utf-8") as handle:
                handle.write("initial\n")
            subprocess.run(["git", "-C", tap, "add", "-A"], check=True)
            subprocess.run(["git", "-C", tap, "commit", "-q", "-m", "init"], check=True)
            subprocess.run(["git", "-C", tap, "push", "-q", "origin", "HEAD:main"], check=True)
            subprocess.run(["git", "-C", tap, "checkout", "-q", "-B", "main"], check=True)

            # A change that has nothing to do with the release, already staged.
            with open(os.path.join(tap, "UNRELATED.md"), "w", encoding="utf-8") as handle:
                handle.write("local edit\n")
            subprocess.run(["git", "-C", tap, "add", "UNRELATED.md"], check=True)

            rh.sha256_of_url = lambda url, timeout=120: NEW_SHA
            try:
                code, _, err = _quiet(rh.main, ["--tap-dir", tap, "--push"])
            finally:
                rh.sha256_of_url = original
            self.assertEqual(code, 0, err)

            committed = subprocess.run(
                ["git", "-C", tap, "show", "--name-only", "--format=", "HEAD"],
                check=True, capture_output=True, text=True,
            ).stdout.split()
            self.assertEqual(committed, [rh.FORMULA_PATH], committed)

            still_staged = subprocess.run(
                ["git", "-C", tap, "diff", "--cached", "--name-only"],
                check=True, capture_output=True, text=True,
            ).stdout.split()
            self.assertEqual(still_staged, ["UNRELATED.md"], still_staged)


if __name__ == "__main__":
    unittest.main()
