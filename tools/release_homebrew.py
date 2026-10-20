#!/usr/bin/env python3
"""release_homebrew - keep the Homebrew tap in step with a release.

Why this exists: the tap pins a url and a sha256 of the release sdist. If a
release does not bump the tap, `brew install` keeps serving the PREVIOUS version
and Homebrew installs it without complaint. A stale tap is worse than no tap,
because it looks current.

This is the release step, and it refuses to write anything it cannot prove:

  1. it reads the version from pyproject.toml (the single source of truth),
  2. it DOWNLOADS the release sdist the formula will point at,
  3. it hashes the bytes it actually received,
  4. only then rewrites the formula, and re-reads the file to confirm,
  5. --push commits and pushes the TAP repo, and nothing else.

Usage:

  python3 tools/release_homebrew.py --check
      Is the published tap current with this tree? Reads the formula from
      GitHub, so it needs no local clone. Exit 0 = current, 1 = stale.

  python3 tools/release_homebrew.py --tap-dir ~/homebrew-nullaosta
      Rewrite the local formula to point at this version. Writes, does not commit.

  python3 tools/release_homebrew.py --tap-dir ~/homebrew-nullaosta --push
      Rewrite, commit and push the tap. Run this AFTER the release assets exist.

Exit codes:
  0  current, or written successfully
  1  stale (--check), or a mismatch, or a failed download
  2  refusal: unreadable tree or formula, or a tap dir inside the source repo

Refusals are decided before any network call, so a bad invocation costs nothing.

Release order (the tap must never point at an asset that does not exist yet):
  bump the version in pyproject.toml -> tag vX.Y.Z -> push the tag ->
  build wheel + sdist -> gh release create with both assets ->
  python3 tools/release_homebrew.py --tap-dir <tap> --push
"""

import argparse
import hashlib
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

OWNER = "domenicoiedera"
REPO = "nullaosta"
TAP_REPO = "homebrew-nullaosta"
TAP_BRANCH = "main"
FORMULA_PATH = "Formula/nullaosta.rb"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

URL_LINE = re.compile(r'^([ \t]*)url[ \t]+"([^"]*)"', re.MULTILINE)
SHA_LINE = re.compile(r'^([ \t]*)sha256[ \t]+"([^"]*)"', re.MULTILINE)
VERSION_LINE = re.compile(r'^version[ \t]*=[ \t]*"([^"]+)"')


def project_version(pyproject_text):
    """The version, from the [project] table only. No toml dependency."""
    in_project = False
    for raw in pyproject_text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_project = line == "[project]"
            continue
        if in_project:
            match = VERSION_LINE.match(line)
            if match:
                return match.group(1)
    raise ValueError("no [project] version found in pyproject.toml")


def sdist_url(version):
    return (
        f"https://github.com/{OWNER}/{REPO}/releases/download/v{version}/"
        f"{REPO}-{version}.tar.gz"
    )


def published_formula_url():
    return (
        f"https://raw.githubusercontent.com/{OWNER}/{TAP_REPO}/"
        f"{TAP_BRANCH}/{FORMULA_PATH}"
    )


def sha256_of_url(url, timeout=120):
    """Hash the bytes actually served, never a value someone typed."""
    digest = hashlib.sha256()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            for chunk in iter(lambda: response.read(65536), b""):
                digest.update(chunk)
    except (urllib.error.URLError, OSError) as exc:
        raise RuntimeError(f"could not download {url}: {exc}") from exc
    return digest.hexdigest()


def fetch_text(url, timeout=60):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.read().decode("utf-8")
    except (urllib.error.URLError, OSError) as exc:
        raise RuntimeError(f"could not fetch {url}: {exc}") from exc


def formula_state(text):
    """(url, sha256) currently pinned by the formula."""
    url_match = URL_LINE.search(text)
    sha_match = SHA_LINE.search(text)
    if not url_match or not sha_match:
        raise ValueError(
            "the formula has no url/sha256 line this tool recognises; "
            "refusing to rewrite something it cannot confirm"
        )
    return url_match.group(2), sha_match.group(2)


def rewrite_formula(text, url, sha):
    """Replace exactly the url and sha256 values, leave every other byte.

    Only the first url/sha256 pair is rewritten, which is correct for this tap:
    it holds one formula and no `resource` blocks. A formula with resources
    would need every pair bumped, and this tool would silently do half the job.
    """
    if not URL_LINE.search(text) or not SHA_LINE.search(text):
        raise ValueError("formula is missing a url or sha256 line")
    text = URL_LINE.sub(lambda m: f'{m.group(1)}url "{url}"', text, count=1)
    text = SHA_LINE.sub(lambda m: f'{m.group(1)}sha256 "{sha}"', text, count=1)
    return text


def is_current(text, url, sha):
    return formula_state(text) == (url, sha)


def _git(tap_dir, *args):
    return subprocess.run(
        ["git", "-C", tap_dir, *args],
        check=True,
        capture_output=True,
        text=True,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Keep the Homebrew tap pinned to this release."
    )
    parser.add_argument("--tap-dir", help=f"local clone of {TAP_REPO}")
    parser.add_argument(
        "--push", action="store_true", help="commit and push the tap after writing"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="only report whether the published tap is current (exit 1 if stale)",
    )
    args = parser.parse_args(argv)

    # ---- refusals first: none of these may cost a network call ----
    if args.check and args.push:
        print("refusing: --check does not write, so --push makes no sense", file=sys.stderr)
        return 2
    if args.push and not args.tap_dir:
        print("refusing: --push needs --tap-dir", file=sys.stderr)
        return 2
    if not args.check and not args.tap_dir:
        print("refusing: pass --check to inspect, or --tap-dir to write", file=sys.stderr)
        return 2

    tap_dir = None
    formula_file = None
    if args.tap_dir:
        tap_dir = os.path.abspath(os.path.expanduser(args.tap_dir))
        real_tap = os.path.realpath(tap_dir)
        real_root = os.path.realpath(ROOT)
        if real_tap == real_root or real_tap.startswith(real_root + os.sep):
            print("refusing: the tap dir is inside the source repo", file=sys.stderr)
            return 2
        formula_file = os.path.join(tap_dir, FORMULA_PATH)
        if not os.path.isfile(formula_file):
            print(f"refusing: no formula at {formula_file}", file=sys.stderr)
            return 2

    try:
        with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as handle:
            version = project_version(handle.read())
    except (OSError, ValueError) as exc:
        print(f"refusing: cannot read the version: {exc}", file=sys.stderr)
        return 2

    url = sdist_url(version)

    try:
        if formula_file:
            with open(formula_file, encoding="utf-8") as handle:
                text = handle.read()
            source = formula_file
        else:
            source = published_formula_url()
            text = fetch_text(source)
        current_url, current_sha = formula_state(text)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"refusing: cannot read the formula: {exc}", file=sys.stderr)
        return 2

    print(f"version   {version}")
    print(f"asset     {url}")
    print(f"formula   {source}")
    print(f"pinned    {current_url}")
    print(f"          {current_sha}")

    # A different url is a version difference: say so without downloading.
    if args.check and current_url != url:
        print(
            f"STALE: the tap points at {current_url} but this tree is {version}",
            file=sys.stderr,
        )
        return 1

    try:
        sha = sha256_of_url(url)
    except RuntimeError as exc:
        print(f"refusing: {exc}", file=sys.stderr)
        print(
            "the release asset must exist before the tap points at it; "
            "create the release first",
            file=sys.stderr,
        )
        return 1
    print(f"sha256    {sha}  (computed from the downloaded bytes)")

    if is_current(text, url, sha):
        print(f"CURRENT: the tap already serves {version} with a matching sha256")
        return 0

    if args.check:
        print(
            f"STALE: the tap's sha256 does not match the published asset for {version}",
            file=sys.stderr,
        )
        return 1

    updated = rewrite_formula(text, url, sha)
    with open(formula_file, "w", encoding="utf-8") as handle:
        handle.write(updated)

    # Re-read from disk: confirm what landed, do not trust the write.
    with open(formula_file, encoding="utf-8") as handle:
        if not is_current(handle.read(), url, sha):
            print("FAILED: the file on disk does not match what was written", file=sys.stderr)
            return 1
    print(f"WROTE     {formula_file}")

    if not args.push:
        print("not pushed: re-run with --push to commit and push the tap")
        return 0

    message = (
        f"{REPO} {version}: bump the formula\n\n"
        f"url    {url}\n"
        f"sha256 {sha}\n\n"
        "Built by tools/release_homebrew.py after the release asset was verified."
    )
    try:
        if not _git(tap_dir, "status", "--porcelain", FORMULA_PATH).stdout.strip():
            print("nothing to commit: the tap is already at this version")
            return 0
        _git(tap_dir, "add", FORMULA_PATH)
        _git(tap_dir, "commit", "-m", message, "--", FORMULA_PATH)
        push = _git(tap_dir, "push", "origin", TAP_BRANCH)
        print(f"PUSHED    {push.stderr.strip() or 'ok'}")
        print(f"tap HEAD  {_git(tap_dir, 'rev-parse', '--short', 'HEAD').stdout.strip()}")
    except subprocess.CalledProcessError as exc:
        print(f"FAILED: git: {(exc.stderr or '').strip() or exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"FAILED: git not runnable in {tap_dir}: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
